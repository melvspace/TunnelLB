mod artifacts;
mod outcomes;
mod runtime;

use std::collections::BTreeMap;

use super::{
    State,
    artifacts::{Artifacts, verify_job, verify_policy, verify_secret},
    identity::{Identity, JOB_UID, KIND_LABEL, MACHINE_UID, REQUEST_HASH, job_reference},
    outcome::{RESULT_LIMIT, WORKER, result},
};
use crate::api::PUBLICATION_LABEL;
use crate::{api, provision, resources};
use k8s_openapi::{
    ByteString,
    api::{
        batch::v1::{Job, JobStatus},
        core::v1::{Pod, Secret},
        networking::v1::NetworkPolicy,
    },
};
use kube::{Resource, ResourceExt};
use serde_json::{Value, json};

const NAMESPACE: &str = "operator";
const SECRET: &str = "sentinel-secret-must-never-escape";

fn machine() -> api::Machine {
    serde_json::from_value(json!({
        "apiVersion": "tunnellb.io/v1alpha1", "kind": "Machine",
        "metadata": {"name": "edge", "uid": "machine-123"},
        "spec": {
            "address": "203.0.113.5",
            "ssh": {"user": "root", "port": 22, "privateKeySecretRef": {"name": "administrator-key"}}
        }
    })).unwrap()
}

fn request() -> provision::Request {
    provision::Request {
        operation: provision::Operation::Enroll,
        generation: None,
        address: "203.0.113.5".parse().unwrap(),
        ssh_user: "root".into(),
        ssh_port: 22,
        machine_uid: "machine-123".into(),
        publication: None,
        server_config: Some(format!("auth.token = \"{SECRET}\"")),
        server_certificate: Some(SECRET.into()),
        server_private_key: Some(SECRET.into()),
        expected_known_hosts: Some("203.0.113.5 ssh-ed25519 AAAA".into()),
    }
}

fn options() -> resources::ResourceOptions {
    resources::ResourceOptions {
        namespace: NAMESPACE.into(),
        image: "example.test/tunnellb@sha256:123".into(),
        pull_policy: "IfNotPresent".into(),
        service_account: "worker".into(),
    }
}

fn mutated<T: serde::Serialize + serde::de::DeserializeOwned>(
    value: &T,
    change: fn(&mut Value),
) -> T {
    let mut value = json!(value);
    change(&mut value);
    serde_json::from_value(value).unwrap()
}

fn artifacts() -> Artifacts {
    let mut artifacts = Artifacts::new(&options(), &machine(), &request(), "revision").unwrap();

    for (metadata, uid, version) in [
        (&mut artifacts.job.metadata, "job-123", "10"),
        (&mut artifacts.secret.metadata, "secret-123", "8"),
        (&mut artifacts.policy.metadata, "policy-123", "9"),
    ] {
        metadata.uid = Some(uid.into());
        metadata.resource_version = Some(version.into());
    }

    artifacts
}

fn identity() -> Identity {
    artifacts().identity
}

fn job() -> Job {
    artifacts().job
}

fn secret() -> Secret {
    artifacts().secret
}

fn policy() -> NetworkPolicy {
    artifacts().policy
}

fn attached<K: Resource>(mut artifact: K) -> K {
    let owner = job_reference(&job()).unwrap();
    let metadata = artifact.meta_mut();
    metadata.owner_references = Some(vec![owner.clone()]);
    metadata
        .annotations
        .get_or_insert_default()
        .insert(JOB_UID.into(), owner.uid);
    artifact
}

fn machine_owned<K: Resource>(mut artifact: K) -> K {
    artifact.meta_mut().owner_references = Some(vec![machine().controller_owner_ref(&()).unwrap()]);
    artifact
}

fn outcome() -> String {
    serde_json::to_string(&provision::Outcome {
        known_hosts: "203.0.113.5 ssh-ed25519 AAAA".into(),
        fingerprint: "SHA256:verified".into(),
        architecture: "amd64".into(),
    })
    .unwrap()
}

fn terminal(mut job: Job, condition: &str) -> Job {
    job.status = Some(
        serde_json::from_value(json!({"conditions": [{
            "type": condition, "status": "True", "reason": "BackoffLimitExceeded", "message": SECRET
        }]}))
        .unwrap(),
    );
    job
}

fn pod(message: Option<String>, exit_code: i32) -> Pod {
    serde_json::from_value(json!({
        "metadata": {
            "name": "worker-pod", "uid": "pod-123", "namespace": NAMESPACE,
            "labels": {"batch.kubernetes.io/job-name": job().name_any()},
            "ownerReferences": [job_reference(&job()).unwrap()]
        },
        "status": {"containerStatuses": [{
            "name": WORKER, "ready": false, "restartCount": 0, "image": "worker", "imageID": "worker",
            "state": {"terminated": {"exitCode": exit_code, "message": message}}
        }]}
    })).unwrap()
}

fn admitted_job(mut job: Job) -> Job {
    // Captured server dry-run changes from the isolated e2e API:
    // hostIPC/hostNetwork/hostPID and false volumeMount.readOnly disappear.
    let spec = job.spec.as_mut().unwrap();
    spec.suspend = Some(false);
    let pod = spec.template.spec.as_mut().unwrap();
    pod.host_ipc = None;
    pod.host_network = None;
    pod.host_pid = None;
    for container in pod
        .containers
        .iter_mut()
        .chain(pod.init_containers.iter_mut().flatten())
    {
        for mount in container.volume_mounts.iter_mut().flatten() {
            if mount.read_only == Some(false) {
                mount.read_only = None;
            }
        }
    }

    job
}
