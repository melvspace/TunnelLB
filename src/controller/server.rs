use crate::{
    api::{SERVER_LABEL, Server, ServerStatus},
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

pub(super) async fn reconcile_server(
    server: Arc<Server>,
    context: Arc<Context>,
) -> Result<Action, ReconcileError> {
    let _lock = context.serial.lock().await;
    match server_inner(&server, &context).await {
        Ok(()) => Ok(context.action()),
        Err(_) => {
            let _ = server_status(&server, &context, "Degraded", "ReconcileFailed",
                "Operation failed; inspect SSH Job state and configuration. Credentials are never included in errors.").await;
            Err(ReconcileError)
        }
    }
}

pub(super) async fn server_inner(server: &Server, context: &Context) -> Result<()> {
    let servers: Api<Server> = Api::all(context.client.clone());

    if server.metadata.deletion_timestamp.is_some() {
        return delete_server(server, context).await;
    }

    let nodes = Api::<Node>::all(context.client.clone())
        .list(&ListParams::default())
        .await?;
    let address = match validation::validate_server(
        server,
        &nodes.items,
        context.config.allow_private_servers,
    ) {
        Ok(address) => address,
        Err(error) => {
            return server_status(
                server,
                context,
                "Invalid",
                "InvalidServer",
                &error.to_string(),
            )
            .await;
        }
    };
    // Duplicate addresses would give two independent ledgers authority over the
    // same host. Refuse both; an existing host owner also enforces UID ownership.
    let all = servers.list(&ListParams::default()).await?;

    if all
        .items
        .iter()
        .any(|other| other.uid() != server.uid() && other.spec.address == server.spec.address)
    {
        for record in context
            .store
            .records(&format!("{SERVER_LABEL}={}", server.name_any()))
            .await?
        {
            terminate_connector(&record.publication, context).await?;
        }

        return server_status(
            server,
            context,
            "Invalid",
            "AddressConflict",
            "Each edge address must belong to exactly one Server.",
        )
        .await;
    }

    if !has_finalizer(server) {
        set_finalizer(&servers, server, true).await?;

        return Ok(());
    }

    let uid = server.uid().context("Server has no UID")?;
    let pin = context.store.pin(&uid).await?;

    if let Some(pin) = &pin
        && (pin.address != server.spec.address || pin.ssh_port != server.spec.ssh.port)
    {
        return server_status(
            server,
            context,
            "Invalid",
            "PinnedAddressChanged",
            "Delete and clean up the Server before changing its SSH address or port.",
        )
        .await;
    }

    let enrolled_revision = enrollment_revision(server, context)?;

    if pin.is_none()
        || server
            .status
            .as_ref()
            .and_then(|s| s.enrolled_revision.as_ref())
            != Some(&enrolled_revision)
    {
        let request = request_for(server, Operation::Enroll, address, pin.as_ref());
        let revision = context.revision(&format!("enroll:{enrolled_revision}"));
        match jobs::run(
            &context.client,
            &context.resources,
            server,
            &request,
            &revision,
        )
        .await?
        {
            State::Pending => {
                if server.status.as_ref().is_none_or(|s| s.phase != "Ready") {
                    server_status(
                        server,
                        context,
                        "Pending",
                        "Enrolling",
                        "Checking the SSH host key and installing the pinned edge runtime.",
                    )
                    .await?;
                }
            }

            State::Failed(_) => {
                server_status(server, context, "Degraded", "SSHFailed", "SSH provisioning failed; check host identity, key, sudo and systemd prerequisites.").await?;
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
                            ssh_port: server.spec.ssh.port,
                        },
                    )
                    .await?;

                if outcome.architecture.is_empty() {
                    server_status(server, context, "Pending", "HostKeyPinned", "First-seen host key persisted; installation will use strict host-key verification.").await?;
                } else {
                    server_status(
                        server,
                        context,
                        "Ready",
                        "Enrolled",
                        "Edge runtime installed and SSH host key pinned.",
                    )
                    .await?;
                }
            }
        }
    } else if server.status.as_ref().is_some_and(|s| s.phase != "Ready") {
        server_status(
            server,
            context,
            "Ready",
            "Enrolled",
            "Previously enrolled runtime configuration is current.",
        )
        .await?;
    }

    Ok(())
}

pub(super) async fn delete_server(server: &Server, context: &Context) -> Result<()> {
    if !has_finalizer(server) {
        return Ok(());
    }

    let uid = server.uid().context("Server UID missing")?;
    let abandon = force_delete(server);
    let mut complete = true;
    for record in context
        .store
        .records(&format!("{SERVER_LABEL}={}", server.name_any()))
        .await?
    {
        if record.publication.server_uid == uid {
            complete &= cleanup_publication(&record, context, abandon).await?;
        }
    }

    if !complete {
        return server_status(
            server,
            context,
            "Deleting",
            "CleanupPending",
            "Waiting for connector termination and remote cleanup.",
        )
        .await;
    }

    if remote_operations_running(context, &format!("{SERVER_LABEL}={}", server.name_any())).await? {
        return Ok(());
    }

    if !abandon && let Some(pin) = context.store.pin(&uid).await? {
        let request = request_for(
            server,
            Operation::Uninstall,
            pin.address.parse()?,
            Some(&pin),
        );
        match jobs::run(
            &context.client,
            &context.resources,
            server,
            &request,
            &context.revision("uninstall"),
        )
        .await?
        {
            State::Pending | State::Failed(_) => {
                return server_status(server, context, "Deleting", "CleanupPending", "Remote uninstall is pending; force-delete explicitly abandons remote resources.").await;
            }

            State::Complete(_) => {}
        }
    }

    jobs::cleanup(
        &context.client,
        &context.config.namespace,
        &format!("{SERVER_LABEL}={}", server.name_any()),
    )
    .await?;
    context.store.gc_allocations(&uid, &BTreeSet::new()).await?;
    context.store.delete_ledger(&uid).await?;
    context.store.delete_pin(&uid).await?;
    set_finalizer(&Api::<Server>::all(context.client.clone()), server, false).await
}

pub(super) fn request_for(
    server: &Server,
    operation: Operation,
    address: Ipv4Addr,
    pin: Option<&HostPin>,
) -> Request {
    Request {
        operation,
        address,
        ssh_user: server.spec.ssh.user.clone(),
        ssh_port: server.spec.ssh.port,
        server_uid: server.uid().unwrap_or_default(),
        publication: None,
        server_config: None,
        server_certificate: None,
        server_private_key: None,
        generation: None,
        reservation: None,
        expected_known_hosts: pin.map(|p| p.known_hosts.clone()),
    }
}

pub(super) fn enrollment_revision(server: &Server, context: &Context) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&json!({
        "image": context.resources.image, "ssh": server.spec.ssh,
        "request": server.annotations().get("tunnellb.io/re-enroll")
    }))?)))
}

pub(super) async fn server_status(
    server: &Server,
    context: &Context,
    phase: &str,
    reason: &str,
    message: &str,
) -> Result<()> {
    let status = ServerStatus {
        enrolled_revision: if phase == "Ready" {
            Some(enrollment_revision(server, context)?)
        } else {
            server
                .status
                .as_ref()
                .and_then(|s| s.enrolled_revision.clone())
        },
        observed_generation: server.metadata.generation.unwrap_or(0),
        phase: phase.into(),
        reason: reason.into(),
        message: message.into(),
    };

    if server.status.as_ref() == Some(&status) {
        return Ok(());
    }

    Api::<Server>::all(context.client.clone())
        .patch_status(
            &server.name_any(),
            &PatchParams::default(),
            &Patch::Merge(json!({"metadata": {"uid": server.uid(), "resourceVersion": server.resource_version()}, "status": status})),
        )
        .await?;
    Ok(())
}
