//! Operator-namespace state with explicit ownership and optimistic concurrency.

mod identities;
mod leases;
mod records;

pub use identities::HostPin;
pub use records::PublicationRecord;

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use k8s_openapi::{api::core::v1::ConfigMap, apimachinery::pkg::apis::meta::v1::ObjectMeta};
use kube::{
    Api, Client,
    api::{DeleteParams, Preconditions},
};
use sha2::{Digest, Sha256};

use crate::api::{MACHINE_LABEL, MANAGED_LABEL, PUBLICATION_LABEL, Publication, SERVICE_UID_LABEL};

const KIND_LABEL: &str = "tunnellb.io/kind";
const MACHINE_UID_LABEL: &str = "tunnellb.io/machine-uid";
const MAX_ATTEMPTS: usize = 8;

pub struct Store {
    pub client: Client,
    pub namespace: String,
}

impl Store {
    pub fn new(client: Client, namespace: String) -> Self {
        Self { client, namespace }
    }

    fn config_maps(&self) -> Api<ConfigMap> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    fn metadata(&self, name: &str, labels: BTreeMap<String, String>) -> ObjectMeta {
        ObjectMeta {
            name: Some(name.into()),
            namespace: Some(self.namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        }
    }

    fn check_owned(
        &self,
        metadata: &ObjectMeta,
        name: &str,
        labels: &BTreeMap<String, String>,
    ) -> Result<()> {
        ensure!(
            metadata.name.as_deref() == Some(name)
                && metadata.namespace.as_deref() == Some(self.namespace.as_str()),
            "state object identity does not match its operator namespace and name"
        );

        for (key, value) in labels {
            ensure!(
                metadata.labels.as_ref().and_then(|labels| labels.get(key)) == Some(value),
                "refusing foreign state object: ownership label {key} does not match"
            );
        }

        ensure!(
            metadata.owner_references.as_ref().is_none_or(Vec::is_empty),
            "refusing state object with another resource owner"
        );
        ensure!(
            metadata.deletion_timestamp.is_none(),
            "state object is being deleted"
        );

        Ok(())
    }
}

fn validate_id(id: &str) -> Result<()> {
    ensure!(
        id.len() == 34
            && id.starts_with("p-")
            && id[2..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid publication ID"
    );

    Ok(())
}

fn owned_labels(kind: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (MANAGED_LABEL.into(), "tunnellb".into()),
        (KIND_LABEL.into(), kind.into()),
    ])
}

fn machine_labels(kind: &str, uid: &str) -> Result<BTreeMap<String, String>> {
    ensure!(!uid.is_empty(), "Machine UID is required");
    let mut labels = owned_labels(kind);
    labels.insert(MACHINE_UID_LABEL.into(), uid.into());

    Ok(labels)
}

fn publication_labels(kind: &str, publication: &Publication) -> Result<BTreeMap<String, String>> {
    validate_id(&publication.id)?;
    ensure!(
        !publication.machine_name.is_empty(),
        "Machine name is required"
    );
    ensure!(
        !publication.service.uid.is_empty()
            && !publication.service.name.is_empty()
            && !publication.service.namespace.is_empty(),
        "Service name, namespace and UID are required"
    );
    let mut labels = machine_labels(kind, &publication.machine_uid)?;
    labels.insert(MACHINE_LABEL.into(), publication.machine_name.clone());
    labels.insert(SERVICE_UID_LABEL.into(), publication.service.uid.clone());
    labels.insert(PUBLICATION_LABEL.into(), publication.id.clone());

    Ok(labels)
}

fn machine_state_name(prefix: &str, uid: &str) -> String {
    format!(
        "{prefix}-{}",
        &hex::encode(Sha256::digest(uid.as_bytes()))[..20]
    )
}

fn config_map_value<'a>(object: &'a ConfigMap, key: &str) -> Result<&'a str> {
    object
        .data
        .as_ref()
        .and_then(|data| data.get(key))
        .map(String::as_str)
        .with_context(|| format!("state ConfigMap is missing {key}"))
}

fn required_label<'a>(metadata: &'a ObjectMeta, key: &str) -> Result<&'a str> {
    metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(key))
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("state object is missing ownership label {key}"))
}

fn resource_version(metadata: &ObjectMeta) -> Result<&str> {
    metadata
        .resource_version
        .as_deref()
        .filter(|version| !version.is_empty())
        .context("state object is missing resourceVersion")
}

fn delete_params(metadata: &ObjectMeta) -> Result<DeleteParams> {
    let uid = metadata
        .uid
        .as_deref()
        .filter(|uid| !uid.is_empty())
        .context("state object is missing its Kubernetes UID")?;

    Ok(DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(uid.into()),
            resource_version: Some(resource_version(metadata)?.into()),
        }),
        ..Default::default()
    })
}

fn has_status(error: &kube::Error, code: u16) -> bool {
    matches!(error, kube::Error::Api(response) if response.code == code)
}

fn retryable_write(error: &kube::Error, replacing: bool) -> bool {
    // AlreadyExists and Conflict are both 409, but have different reasons.
    has_status(error, 409) || (replacing && has_status(error, 404))
}

fn delete_result<T>(result: std::result::Result<T, kube::Error>) -> Result<()> {
    match result {
        Ok(_) => Ok(()),
        Err(error) if has_status(&error, 404) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests;
