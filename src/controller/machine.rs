use crate::{
    api::{MACHINE_LABEL, Machine, MachineStatus},
    jobs::{self, State},
    provision::{Operation, Request},
    store::HostPin,
    validation,
};
use anyhow::{Context as _, Result};
use k8s_openapi::api::core::v1::Node;
use kube::{
    Api, ResourceExt,
    api::{ListParams, Patch, PatchParams},
    runtime::controller::Action,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, net::Ipv4Addr, sync::Arc};

use super::{
    Context, ReconcileError,
    kubernetes::{force_delete, has_finalizer, set_finalizer},
    publication::{cleanup_publication, remote_operations_running, terminate_connector},
};

pub(super) async fn reconcile_machine(
    machine: Arc<Machine>,
    context: Arc<Context>,
) -> Result<Action, ReconcileError> {
    let _lock = context.serial.lock().await;
    match machine_inner(&machine, &context).await {
        Ok(()) => Ok(context.action()),
        Err(_) => {
            let _ = machine_status(&machine, &context, "Degraded", "ReconcileFailed",
                "Operation failed; inspect SSH Job state and configuration. Credentials are never included in errors.").await;
            Err(ReconcileError)
        }
    }
}

pub(super) async fn machine_inner(machine: &Machine, context: &Context) -> Result<()> {
    let machines: Api<Machine> = Api::all(context.client.clone());

    if machine.metadata.deletion_timestamp.is_some() {
        return delete_machine(machine, context).await;
    }

    let nodes = Api::<Node>::all(context.client.clone())
        .list(&ListParams::default())
        .await?;
    let address = match validation::validate_machine(
        machine,
        &nodes.items,
        context.config.allow_private_machines,
    ) {
        Ok(address) => address,
        Err(error) => {
            return machine_status(
                machine,
                context,
                "Invalid",
                "InvalidMachine",
                &error.to_string(),
            )
            .await;
        }
    };
    // Duplicate addresses would give two independent ledgers authority over the
    // same host. Refuse both; an existing host owner also enforces UID ownership.
    let all = machines.list(&ListParams::default()).await?;

    if all
        .items
        .iter()
        .any(|other| other.uid() != machine.uid() && other.spec.address == machine.spec.address)
    {
        for record in context
            .store
            .records(&format!("{MACHINE_LABEL}={}", machine.name_any()))
            .await?
        {
            terminate_connector(&record.publication, context).await?;
        }

        return machine_status(
            machine,
            context,
            "Invalid",
            "AddressConflict",
            "Each edge address must belong to exactly one Machine.",
        )
        .await;
    }

    if !has_finalizer(machine) {
        set_finalizer(&machines, machine, true).await?;

        return Ok(());
    }

    let uid = machine.uid().context("Machine has no UID")?;
    let pin = context.store.pin(&uid).await?;

    if let Some(pin) = &pin
        && (pin.address != machine.spec.address || pin.ssh_port != machine.spec.ssh.port)
    {
        return machine_status(
            machine,
            context,
            "Invalid",
            "PinnedAddressChanged",
            "Delete and clean up the Machine before changing its SSH address or port.",
        )
        .await;
    }

    let enrolled_revision = enrollment_revision(machine, context)?;

    if pin.is_none()
        || machine
            .status
            .as_ref()
            .and_then(|s| s.enrolled_revision.as_ref())
            != Some(&enrolled_revision)
    {
        let request = request_for(machine, Operation::Enroll, address, pin.as_ref());
        let revision = context.revision(&format!("enroll:{enrolled_revision}"));
        match jobs::run(
            &context.client,
            &context.resources,
            machine,
            &request,
            &revision,
        )
        .await?
        {
            State::Pending => {
                if machine.status.as_ref().is_none_or(|s| s.phase != "Ready") {
                    machine_status(
                        machine,
                        context,
                        "Pending",
                        "Enrolling",
                        "Checking the SSH host key and installing the pinned edge runtime.",
                    )
                    .await?;
                }
            }

            State::Failed(_) => {
                machine_status(machine, context, "Degraded", "SSHFailed", "SSH provisioning failed; check host identity, key, sudo and systemd prerequisites.").await?;
            }

            State::Complete(outcome) => {
                context
                    .store
                    .save_pin(
                        &uid,
                        &HostPin {
                            known_hosts: outcome.known_hosts,
                            fingerprint: outcome.fingerprint,
                            address: address.to_string(),
                            ssh_port: machine.spec.ssh.port,
                        },
                    )
                    .await?;

                if outcome.architecture.is_empty() {
                    machine_status(machine, context, "Pending", "HostKeyPinned", "First-seen host key persisted; installation will use strict host-key verification.").await?;
                } else {
                    machine_status(
                        machine,
                        context,
                        "Ready",
                        "Enrolled",
                        "Edge runtime installed and SSH host key pinned.",
                    )
                    .await?;
                }
            }
        }
    } else if machine.status.as_ref().is_some_and(|s| s.phase != "Ready") {
        machine_status(
            machine,
            context,
            "Ready",
            "Enrolled",
            "Previously enrolled runtime configuration is current.",
        )
        .await?;
    }

    Ok(())
}

pub(super) async fn delete_machine(machine: &Machine, context: &Context) -> Result<()> {
    if !has_finalizer(machine) {
        return Ok(());
    }

    let uid = machine.uid().context("Machine UID missing")?;
    let abandon = force_delete(machine);
    let mut complete = true;
    for record in context
        .store
        .records(&format!("{MACHINE_LABEL}={}", machine.name_any()))
        .await?
    {
        if record.publication.machine_uid == uid {
            complete &= cleanup_publication(&record, context, abandon).await?;
        }
    }

    if !complete {
        return machine_status(
            machine,
            context,
            "Deleting",
            "CleanupPending",
            "Waiting for connector termination and remote cleanup.",
        )
        .await;
    }

    if remote_operations_running(context, &format!("{MACHINE_LABEL}={}", machine.name_any()))
        .await?
    {
        return Ok(());
    }

    if !abandon && let Some(pin) = context.store.pin(&uid).await? {
        let request = request_for(
            machine,
            Operation::Uninstall,
            pin.address.parse()?,
            Some(&pin),
        );
        match jobs::run(
            &context.client,
            &context.resources,
            machine,
            &request,
            &context.revision("uninstall"),
        )
        .await?
        {
            State::Pending | State::Failed(_) => {
                return machine_status(machine, context, "Deleting", "CleanupPending", "Remote uninstall is pending; force-delete explicitly abandons remote resources.").await;
            }

            State::Complete(_) => {}
        }
    }

    jobs::cleanup(
        &context.client,
        &context.config.namespace,
        &format!("{MACHINE_LABEL}={}", machine.name_any()),
    )
    .await?;
    context.store.gc_allocations(&uid, &BTreeSet::new()).await?;
    context.store.delete_ledger(&uid).await?;
    context.store.delete_pin(&uid).await?;
    set_finalizer(&Api::<Machine>::all(context.client.clone()), machine, false).await
}

pub(super) fn request_for(
    machine: &Machine,
    operation: Operation,
    address: Ipv4Addr,
    pin: Option<&HostPin>,
) -> Request {
    Request {
        operation,
        address,
        ssh_user: machine.spec.ssh.user.clone(),
        ssh_port: machine.spec.ssh.port,
        machine_uid: machine.uid().unwrap_or_default(),
        publication: None,
        server_config: None,
        server_certificate: None,
        server_private_key: None,
        generation: None,
        expected_known_hosts: pin.map(|p| p.known_hosts.clone()),
    }
}

pub(super) fn enrollment_revision(machine: &Machine, context: &Context) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&json!({
        "image": context.resources.image, "ssh": machine.spec.ssh,
        "request": machine.annotations().get("tunnellb.io/re-enroll")
    }))?)))
}

pub(super) async fn machine_status(
    machine: &Machine,
    context: &Context,
    phase: &str,
    reason: &str,
    message: &str,
) -> Result<()> {
    let status = MachineStatus {
        enrolled_revision: if phase == "Ready" {
            Some(enrollment_revision(machine, context)?)
        } else {
            machine
                .status
                .as_ref()
                .and_then(|s| s.enrolled_revision.clone())
        },
        observed_generation: machine.metadata.generation.unwrap_or(0),
        phase: phase.into(),
        reason: reason.into(),
        message: message.into(),
    };

    if machine.status.as_ref() == Some(&status) {
        return Ok(());
    }

    Api::<Machine>::all(context.client.clone())
        .patch_status(
            &machine.name_any(),
            &PatchParams::default(),
            &Patch::Merge(json!({"metadata": {"uid": machine.uid(), "resourceVersion": machine.resource_version()}, "status": status})),
        )
        .await?;
    Ok(())
}
