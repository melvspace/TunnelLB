use crate::{
    api::{
        MACHINE_LABEL, MANAGED_LABEL, Machine, PUBLICATION_LABEL, Publication, SERVICE_UID_LABEL,
    },
    connector::GuardConfig,
    jobs::{self, State},
    provision::Operation,
    resources::{self, ResourceOptions},
    store::PublicationRecord,
    transport,
};
use anyhow::{Context as _, Result, ensure};
use k8s_openapi::{
    ByteString,
    api::{
        apps::v1::{Deployment, ReplicaSet},
        batch::v1::Job,
        core::v1::{Pod, Secret},
        networking::v1::NetworkPolicy,
    },
    apimachinery::pkg::apis::meta::v1::ObjectMeta,
};
use kube::{Api, ResourceExt, api::ListParams};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use super::{
    Context,
    kubernetes::{apply_owned, delete_owned},
    machine::request_for,
};

pub(super) async fn ensure_publication(
    record: &mut PublicationRecord,
    machine: &Machine,
    context: &Context,
) -> Result<bool> {
    ensure!(
        !record.removing,
        "cannot restore a publication committed to removal"
    );
    let publication = record.publication.clone();
    let deployments: Api<Deployment> = context.api();
    let existing = deployments.get_opt(&publication.id).await?;
    let matching = existing
        .as_ref()
        .is_some_and(|deployment| connector_matches(deployment, &record.config_hash));

    // The actual template, not the already-saved desired hash, proves which
    // connector is running after a crash. Drain orphan children even when the
    // Deployment has disappeared before changing its Secret or recreating it.
    if !matching && !terminate_connector(&publication, context).await? {
        return Ok(false);
    }

    ensure!(
        context
            .store
            .allocate(machine, &publication.service, &publication.id)
            .await?
            == publication.control_port,
        "publication lease differs from persisted control port"
    );
    let Some(pin) = context.store.pin(&publication.machine_uid).await? else {
        return Ok(false);
    };
    ensure!(
        pin.address == publication.machine_address.to_string()
            && pin.ssh_port == machine.spec.ssh.port,
        "pinned address mismatch"
    );
    let credentials = context.store.credentials(&publication).await?;
    let generation = transport::credential_generation(&credentials.certificate_pem);

    if record.credential_generation.as_ref() != Some(&generation) {
        ensure!(
            record.credential_generation.is_none(),
            "publication credentials changed unexpectedly"
        );
        record.credential_generation = Some(generation.clone());
        context.store.save_record(record).await?;
    }

    let healthy = matching && existing.as_ref().is_some_and(deployment_ready);

    if record.applied_hash.as_ref() != Some(&record.config_hash) || (matching && !healthy) {
        // Unready connectors reuse the immutable Job result within each
        // ten-minute revision bucket. A later bucket can repair a lost remote
        // unit while connectors independently reconnect; jobs serialize workers.
        let mut request = request_for(
            machine,
            Operation::Apply,
            publication.machine_address,
            Some(&pin),
        );
        request.publication = Some(publication.clone());
        request.generation = Some(generation);
        request.server_config = Some(transport::server_config(&publication, &credentials)?);
        request.server_certificate = Some(credentials.certificate_pem.clone());
        request.server_private_key = Some(credentials.private_key_pem.clone());
        let revision = context.revision(&format!(
            "apply:{}:{}",
            record.config_hash,
            serde_json::to_string(&machine.spec.ssh)?
        ));
        match jobs::run(
            &context.client,
            &context.resources,
            machine,
            &request,
            &revision,
        )
        .await?
        {
            State::Pending | State::Failed(_) => {
                // Existing clients retain last configuration through edge/API outages.
                if record.applied_hash.as_ref() != Some(&record.config_hash) {
                    return Ok(false);
                }
            }

            State::Complete(_) => {
                record.applied_hash = Some(record.config_hash.clone());
                context.store.save_record(record).await?;
            }
        }
    }

    if record.applied_hash.as_ref() != Some(&record.config_hash) {
        return Ok(false);
    }

    let config = transport::client_config(&publication, &credentials)?;
    let secret_name = format!("client-{}", publication.id);
    let secret = Secret {
        metadata: publication_metadata(&secret_name, &publication, &context.config.namespace),
        type_: Some("Opaque".into()),
        data: Some(BTreeMap::from([
            ("frpc.toml".into(), ByteString(config.into_bytes())),
            (
                "ca.crt".into(),
                ByteString(credentials.certificate_pem.into_bytes()),
            ),
            (
                "guard.json".into(),
                ByteString(serde_json::to_vec(&GuardConfig::for_publication(
                    &publication,
                ))?),
            ),
        ])),
        ..Default::default()
    };
    apply_owned(&context.api::<Secret>(), &secret).await?;
    let policy =
        resources::connector_policy(&publication, &record.backend_ports, &context.resources);
    apply_owned(&context.api::<NetworkPolicy>(), &policy).await?;
    let deployment = resources::connector_deployment(
        &publication,
        &record.backend_ports,
        &secret_name,
        &context.resources,
        &record.config_hash,
    );
    apply_owned(&deployments, &deployment).await?;
    let healthy = deployments
        .get(&publication.id)
        .await
        .is_ok_and(|d| deployment_ready(&d));

    if healthy {
        record.published = true;
    }

    context.store.save_record(record).await?;
    Ok(healthy)
}

pub(super) async fn terminate_connector(
    publication: &Publication,
    context: &Context,
) -> Result<bool> {
    delete_owned(
        &context.api::<Deployment>(),
        &publication.id,
        Some(&publication.id),
    )
    .await?;
    let pods: Api<Pod> = context.api();
    let list = pods
        .list(&ListParams::default().labels(&format!(
            "{MANAGED_LABEL}=tunnellb,{PUBLICATION_LABEL}={}",
            publication.id
        )))
        .await?;
    let mut stopped = context
        .api::<Deployment>()
        .get_opt(&publication.id)
        .await?
        .is_none();
    stopped &= context
        .api::<ReplicaSet>()
        .list(&ListParams::default().labels(&format!(
            "{MANAGED_LABEL}=tunnellb,{PUBLICATION_LABEL}={}",
            publication.id
        )))
        .await?
        .items
        .is_empty();
    for pod in list {
        // SSH workers carry the publication label too; never treat their life
        // cycle as a connector or terminate the cleanup operation itself.
        if !pod
            .spec
            .as_ref()
            .is_some_and(|s| s.containers.iter().any(|c| c.name == "connector"))
        {
            continue;
        }

        let terminal = pod
            .status
            .as_ref()
            .and_then(|s| s.phase.as_deref())
            .is_some_and(|p| matches!(p, "Succeeded" | "Failed"));

        if !terminal {
            stopped = false;

            if pod.metadata.deletion_timestamp.is_none() {
                delete_owned(&pods, &pod.name_any(), Some(&publication.id)).await?;
            }
        }
    }

    Ok(stopped)
}

pub(super) async fn cleanup_publication(
    record: &PublicationRecord,
    context: &Context,
    abandon: bool,
) -> Result<bool> {
    if !record.removing {
        let mut removing = record.clone();
        removing.removing = true;
        context.store.save_record(&removing).await?;
    }

    let publication = &record.publication;

    if !terminate_connector(publication, context).await? {
        return Ok(false);
    }

    if remote_operations_running(context, &format!("{PUBLICATION_LABEL}={}", publication.id))
        .await?
    {
        return Ok(false);
    }

    let mut machine = Machine::new(&publication.machine_name, record.machine_spec.clone());
    machine.metadata.uid = Some(publication.machine_uid.clone());
    let pin = context.store.pin(&publication.machine_uid).await?;

    if !abandon && record.credential_generation.is_some() {
        let pin = pin.context("cannot clean remote publication without persisted host pin")?;
        let mut request = request_for(
            &machine,
            Operation::Remove,
            publication.machine_address,
            Some(&pin),
        );
        request.publication = Some(publication.clone());
        request.generation = record.credential_generation.clone();
        match jobs::run(
            &context.client,
            &context.resources,
            &machine,
            &request,
            &context.revision("remove"),
        )
        .await?
        {
            State::Pending | State::Failed(_) => return Ok(false),
            State::Complete(_) => {}
        }
    }

    ensure!(
        abandon || record.credential_generation.is_some() || record.applied_hash.is_none(),
        "missing generation for an applied publication"
    );
    jobs::cleanup(
        &context.client,
        &context.config.namespace,
        &format!("{PUBLICATION_LABEL}={}", publication.id),
    )
    .await?;
    delete_owned(
        &context.api::<Secret>(),
        &format!("client-{}", publication.id),
        Some(&publication.id),
    )
    .await?;
    delete_owned(
        &context.api::<NetworkPolicy>(),
        &publication.id,
        Some(&publication.id),
    )
    .await?;
    context.store.delete_credentials(&publication.id).await?;
    context
        .store
        .release(&publication.machine_uid, &publication.id)
        .await?;
    context.store.delete_record(&publication.id).await?;
    Ok(true)
}

pub(super) async fn remote_operations_running(context: &Context, selector: &str) -> Result<bool> {
    let jobs = context
        .api::<Job>()
        .list(&ListParams::default().labels(&format!(
            "{MANAGED_LABEL}=tunnellb,tunnellb.io/kind=ssh-job,{selector}"
        )))
        .await?;
    Ok(jobs.items.iter().any(|job| {
        !job.status
            .as_ref()
            .and_then(|s| s.conditions.as_ref())
            .is_some_and(|conditions| {
                conditions.iter().any(|c| {
                    c.status == "True" && matches!(c.type_.as_str(), "Complete" | "Failed")
                })
            })
    }))
}

pub fn publication_id(service_uid: &str, machine_uid: &str) -> String {
    format!(
        "p-{}",
        &hex::encode(Sha256::digest(format!("{service_uid}/{machine_uid}")))[..32]
    )
}

pub(super) fn publication_hash(
    publication: &Publication,
    options: &ResourceOptions,
) -> Result<String> {
    // Endpoint changes update policy only, preserving established connections.
    let value = json!({
        "edge": publication.machine_address, "control": publication.control_port,
        "ip": publication.service.cluster_ip, "ports": publication.service.ports,
        "selector": publication.service.selector, "image": options.image,
        "pullPolicy": options.pull_policy, "worker": options.service_account,
        "frp": transport::FRP_VERSION,
    });
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&value)?)))
}

pub(super) fn deployment_ready(deployment: &Deployment) -> bool {
    deployment.metadata.deletion_timestamp.is_none()
        && deployment.status.as_ref().is_some_and(|s| {
            s.observed_generation >= deployment.metadata.generation
                && s.available_replicas.unwrap_or(0) > 0
                && s.updated_replicas.unwrap_or(0) > 0
        })
}

pub(super) fn connector_matches(deployment: &Deployment, hash: &str) -> bool {
    deployment.metadata.deletion_timestamp.is_none()
        && deployment
            .spec
            .as_ref()
            .and_then(|spec| spec.template.metadata.as_ref())
            .and_then(|metadata| metadata.annotations.as_ref())
            .and_then(|annotations| annotations.get("tunnellb.io/config-hash"))
            .map(String::as_str)
            == Some(hash)
}

pub(super) fn publication_metadata(
    name: &str,
    publication: &Publication,
    namespace: &str,
) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.into()),
        namespace: Some(namespace.into()),
        labels: Some(BTreeMap::from([
            (MANAGED_LABEL.into(), "tunnellb".into()),
            (PUBLICATION_LABEL.into(), publication.id.clone()),
            (MACHINE_LABEL.into(), publication.machine_name.clone()),
            (SERVICE_UID_LABEL.into(), publication.service.uid.clone()),
        ])),
        ..Default::default()
    }
}
