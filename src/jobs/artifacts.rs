//! Build immutable request artifacts and compare their effective Kubernetes configuration.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, ensure};
use k8s_openapi::{
    ByteString,
    api::{
        batch::v1::{Job, JobSpec},
        core::v1::Secret,
        networking::v1::{NetworkPolicy, NetworkPolicyPeer, NetworkPolicyPort, NetworkPolicySpec},
    },
    apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference},
};
use kube::ResourceExt;
use serde_json::Value;

use super::identity::{Identity, request_hash};
use crate::{api, provision, resources};

pub(super) struct Artifacts {
    pub(super) identity: Identity,
    pub(super) job: Job,
    pub(super) secret: Secret,
    pub(super) policy: NetworkPolicy,
}

impl Artifacts {
    /// Validate the Machine scope before embedding credentials. Names bind the
    /// exact serialized request and revision; credentials never enter metadata.
    pub(super) fn new(
        options: &resources::ResourceOptions,
        machine: &api::Machine,
        request: &provision::Request,
        revision: &str,
    ) -> Result<Self> {
        ensure!(
            machine.uid().as_deref() == Some(request.machine_uid.as_str())
                && machine.spec.address == request.address.to_string()
                && machine.spec.ssh.user == request.ssh_user
                && machine.spec.ssh.port == request.ssh_port,
            "SSH request does not match its Machine"
        );

        if let Some(publication) = &request.publication {
            ensure!(
                publication.machine_uid == request.machine_uid
                    && publication.machine_name == machine.name_any()
                    && publication.machine_address.to_string() == machine.spec.address,
                "SSH publication does not match its Machine"
            );
        }

        let request_bytes =
            serde_json::to_vec(request).map_err(|_| anyhow!("could not serialize SSH request"))?;
        let hash = request_hash(&request_bytes, revision);
        let name = format!("job-{}", &hash[..32]);
        let identity = Identity {
            namespace: options.namespace.clone(),
            name,
            machine: machine.name_any(),
            machine_uid: request.machine_uid.clone(),
            publication: request.publication.as_ref().map(|p| p.id.clone()),
            hash,
        };

        let address = machine
            .spec
            .address
            .parse()
            .map_err(|_| anyhow!("SSH Machine requires an IPv4 address"))?;
        let key = &machine.spec.ssh.private_key_secret_ref;
        let mut job = resources::ssh_job(
            &identity.name,
            address,
            request.ssh_port,
            &identity.name,
            &key.name,
            &key.key,
            options,
        );
        let mut policy = resources::ssh_policy(&identity.name, address, request.ssh_port, options);
        identity.stamp(&mut job.metadata);
        identity.stamp(&mut policy.metadata);

        if let Some(template) = job.spec.as_mut().and_then(|s| s.template.metadata.as_mut()) {
            // Keep the builder's selector labels while exposing the operation's scope.
            template
                .labels
                .get_or_insert_default()
                .extend(identity.labels());
        }

        let mut secret = Secret {
            immutable: Some(true),
            type_: Some("Opaque".into()),
            data: Some(BTreeMap::from([(
                "request.json".into(),
                ByteString(request_bytes),
            )])),
            ..Default::default()
        };

        identity.stamp(&mut secret.metadata);

        Ok(Self {
            identity,
            job,
            secret,
            policy,
        })
    }
}

pub(super) fn verify_job(actual: &Job, wanted: &Job, identity: &Identity) -> Result<()> {
    identity.verify(&actual.metadata, None)?;
    // Admission/defaulting can add fields; supplied security settings must survive.
    let actual_spec = serde_json::to_value(normalized_job(actual.spec.clone()))
        .map_err(|_| anyhow!("could not inspect SSH Job"))?;
    let wanted_spec = serde_json::to_value(normalized_job(wanted.spec.clone()))
        .map_err(|_| anyhow!("could not inspect SSH Job"))?;
    ensure!(
        contains(&actual_spec, &wanted_spec),
        "SSH Job configuration mismatch"
    );
    Ok(())
}

fn normalized_job(spec: Option<JobSpec>) -> Option<JobSpec> {
    let mut spec = spec?;

    if let Some(pod) = &mut spec.template.spec {
        // These fields have an unconditional false default and are omitted by
        // the API's serializer. Do not generalize to security settings with
        // inherited or permissive defaults (e.g. automount or escalation).
        pod.host_ipc.get_or_insert(false);
        pod.host_network.get_or_insert(false);
        pod.host_pid.get_or_insert(false);
        for container in pod
            .containers
            .iter_mut()
            .chain(pod.init_containers.iter_mut().flatten())
        {
            for mount in container.volume_mounts.iter_mut().flatten() {
                mount.read_only.get_or_insert(false);
            }
        }
    }

    Some(spec)
}

fn contains(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::Object(a), Value::Object(e)) => e
            .iter()
            .all(|(k, v)| a.get(k).is_some_and(|a| contains(a, v))),
        (Value::Array(a), Value::Array(e)) => {
            a.len() == e.len() && a.iter().zip(e).all(|(a, e)| contains(a, e))
        }

        _ => actual == expected,
    }
}

pub(super) fn verify_secret(
    actual: &Secret,
    wanted: &Secret,
    id: &Identity,
    job: Option<&OwnerReference>,
) -> Result<()> {
    id.verify(&actual.metadata, job)?;
    ensure!(
        actual.immutable == Some(true)
            && actual.data == wanted.data
            && actual.type_ == wanted.type_,
        "SSH request Secret configuration mismatch"
    );
    Ok(())
}

pub(super) fn verify_policy(
    actual: &NetworkPolicy,
    wanted: &NetworkPolicy,
    id: &Identity,
    job: Option<&OwnerReference>,
) -> Result<()> {
    id.verify(&actual.metadata, job)?;
    ensure!(
        normalized_policy(actual.spec.clone()) == normalized_policy(wanted.spec.clone()),
        "SSH NetworkPolicy configuration mismatch"
    );
    Ok(())
}

fn normalized_policy(spec: Option<NetworkPolicySpec>) -> Option<NetworkPolicySpec> {
    let mut spec = spec?;
    omit_empty(&mut spec.ingress);
    omit_empty(&mut spec.egress);
    omit_empty(&mut spec.policy_types);

    if spec.policy_types.is_none() {
        let mut types = vec!["Ingress".into()];

        if spec.egress.is_some() {
            types.push("Egress".into());
        }

        spec.policy_types = Some(types);
    }

    spec.policy_types.as_mut().unwrap().sort();
    normalize_selector(spec.pod_selector.get_or_insert_default());
    for rule in spec.ingress.iter_mut().flatten() {
        normalize_ports(&mut rule.ports);
        normalize_peers(&mut rule.from);
    }

    for rule in spec.egress.iter_mut().flatten() {
        normalize_ports(&mut rule.ports);
        normalize_peers(&mut rule.to);
    }

    Some(spec)
}

fn omit_empty<T>(items: &mut Option<Vec<T>>) {
    if items.as_ref().is_some_and(Vec::is_empty) {
        *items = None;
    }
}

fn normalize_selector(selector: &mut LabelSelector) {
    if selector
        .match_labels
        .as_ref()
        .is_some_and(BTreeMap::is_empty)
    {
        selector.match_labels = None;
    }

    omit_empty(&mut selector.match_expressions);
}

fn normalize_ports(ports: &mut Option<Vec<NetworkPolicyPort>>) {
    omit_empty(ports);
    for port in ports.iter_mut().flatten() {
        port.protocol.get_or_insert_with(|| "TCP".into());
    }
}

fn normalize_peers(peers: &mut Option<Vec<NetworkPolicyPeer>>) {
    omit_empty(peers);
    for peer in peers.iter_mut().flatten() {
        if let Some(selector) = &mut peer.pod_selector {
            normalize_selector(selector);
        }

        if let Some(selector) = &mut peer.namespace_selector {
            normalize_selector(selector);
        }

        if let Some(block) = &mut peer.ip_block {
            omit_empty(&mut block.except);
        }

        // A missing namespace/pod selector and an explicit empty selector have
        // different scopes. Preserve the selector's presence.
    }
}
