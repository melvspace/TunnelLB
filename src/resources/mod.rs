//! Kubernetes resources for isolated connector and SSH-worker pods.
//!
//! Callers provide validated Kubernetes names and immutable, operator-namespace
//! Secrets. They must install the matching policy before starting the workload.

mod network_policy;
mod pod;
mod workloads;

pub use network_policy::{connector_policy, ssh_policy};
pub use workloads::{connector_deployment, ssh_job};

use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};

use crate::api::{MANAGED_LABEL, PUBLICATION_LABEL, Publication, SERVER_LABEL, SERVICE_UID_LABEL};

const SSH_JOB_LABEL: &str = "tunnellb.io/ssh-job";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceOptions {
    /// Namespace containing the workloads, their policies, and all mounted Secrets.
    pub namespace: String,
    pub image: String,
    pub pull_policy: String,
    pub service_account: String,
}

fn publication_labels(publication: &Publication) -> BTreeMap<String, String> {
    BTreeMap::from([
        (MANAGED_LABEL.into(), "tunnellb".into()),
        (PUBLICATION_LABEL.into(), publication.id.clone()),
        (SERVER_LABEL.into(), publication.server_name.clone()),
        (SERVICE_UID_LABEL.into(), publication.service.uid.clone()),
        (
            "tunnellb.io/service-namespace".into(),
            publication.service.namespace.clone(),
        ),
        (
            "tunnellb.io/service-name".into(),
            publication.service.name.clone(),
        ),
    ])
}

fn ssh_labels(name: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (MANAGED_LABEL.into(), "tunnellb".into()),
        (SSH_JOB_LABEL.into(), name.into()),
    ])
}

fn metadata(name: &str, labels: BTreeMap<String, String>, options: &ResourceOptions) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.into()),
        namespace: Some(options.namespace.clone()),
        labels: Some(labels),
        ..Default::default()
    }
}

fn selector(labels: BTreeMap<String, String>) -> LabelSelector {
    LabelSelector {
        match_labels: Some(labels),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests;
