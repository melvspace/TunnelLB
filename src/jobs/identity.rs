//! Content addresses and ownership shared by reconciliation and cleanup.

use std::collections::BTreeMap;

use crate::api::{MACHINE_LABEL, MANAGED_LABEL, PUBLICATION_LABEL};
use anyhow::{Result, anyhow, ensure};
use k8s_openapi::{
    api::batch::v1::Job,
    apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference},
};
use kube::ResourceExt;
use sha2::{Digest, Sha256};

pub(super) const KIND_LABEL: &str = "tunnellb.io/kind";
pub(super) const MACHINE_UID: &str = "tunnellb.io/machine-uid";
pub(super) const REQUEST_HASH: &str = "tunnellb.io/request-hash";
pub(super) const JOB_UID: &str = "tunnellb.io/job-uid";

pub(super) fn request_hash(bytes: &[u8], revision: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(bytes);
    hash.update(revision.as_bytes());
    hex::encode(hash.finalize())
}

/// Binds an artifact to one request, Machine incarnation, and namespace.
pub(super) struct Identity {
    pub(super) namespace: String,
    pub(super) name: String,
    pub(super) machine: String,
    pub(super) machine_uid: String,
    pub(super) publication: Option<String>,
    pub(super) hash: String,
}

impl Identity {
    pub(super) fn labels(&self) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::from([
            (MANAGED_LABEL.into(), "tunnellb".into()),
            (KIND_LABEL.into(), "ssh-job".into()),
            (MACHINE_LABEL.into(), self.machine.clone()),
        ]);

        if let Some(publication) = &self.publication {
            labels.insert(PUBLICATION_LABEL.into(), publication.clone());
        }

        labels
    }

    /// Jobs and staged dependents must survive deletion of their Machine.
    pub(super) fn stamp(&self, metadata: &mut ObjectMeta) {
        metadata.name = Some(self.name.clone());
        metadata.namespace = Some(self.namespace.clone());
        metadata
            .labels
            .get_or_insert_default()
            .extend(self.labels());
        metadata.annotations.get_or_insert_default().extend([
            (MACHINE_UID.into(), self.machine_uid.clone()),
            (REQUEST_HASH.into(), self.hash.clone()),
        ]);
        metadata.owner_references = None;
    }

    /// Scope is established by namespace, labels, Machine UID and request hash.
    /// Accept no owner, or the exact dependent Job owner and UID annotation.
    pub(super) fn verify(&self, metadata: &ObjectMeta, job: Option<&OwnerReference>) -> Result<()> {
        let labels = metadata.labels.as_ref();
        let annotations = metadata.annotations.as_ref();
        ensure!(
            metadata.name.as_deref() == Some(&self.name)
                && metadata.namespace.as_deref() == Some(&self.namespace)
                && self
                    .labels()
                    .iter()
                    .all(|(k, v)| labels.and_then(|l| l.get(k)) == Some(v))
                && labels.and_then(|l| l.get(PUBLICATION_LABEL)) == self.publication.as_ref()
                && annotations.and_then(|a| a.get(MACHINE_UID)) == Some(&self.machine_uid)
                && annotations.and_then(|a| a.get(REQUEST_HASH)) == Some(&self.hash),
            "SSH artifact ownership mismatch"
        );
        let owners = metadata.owner_references.as_deref().unwrap_or_default();
        let staged = owners.is_empty() && annotations.and_then(|a| a.get(JOB_UID)).is_none();
        let attached = job.is_some_and(|job| {
            owners.len() == 1
                && same_owner(&owners[0], job)
                && annotations.and_then(|a| a.get(JOB_UID)) == Some(&job.uid)
        });
        ensure!(staged || attached, "SSH artifact has a foreign owner");
        Ok(())
    }

    pub(super) fn from_metadata(metadata: &ObjectMeta, namespace: &str) -> Option<Self> {
        let labels = metadata.labels.as_ref()?;
        let annotations = metadata.annotations.as_ref()?;
        let hash = annotations.get(REQUEST_HASH)?.clone();
        let name = metadata.name.clone()?;
        let machine = labels.get(MACHINE_LABEL)?.clone();
        let machine_uid = annotations.get(MACHINE_UID)?.clone();

        if hash.len() != 64
            || !hash.bytes().all(|b| b.is_ascii_hexdigit())
            || name != format!("job-{}", &hash[..32])
            || machine.is_empty()
            || machine_uid.is_empty()
        {
            return None;
        }

        Some(Self {
            namespace: namespace.into(),
            name,
            machine,
            machine_uid,
            publication: labels.get(PUBLICATION_LABEL).cloned(),
            hash,
        })
    }
}

pub(super) fn same_owner(actual: &OwnerReference, expected: &OwnerReference) -> bool {
    actual.api_version == expected.api_version
        && actual.kind == expected.kind
        && actual.name == expected.name
        && actual.uid == expected.uid
        && actual.controller == Some(true)
}

pub(super) fn job_reference(job: &Job) -> Result<OwnerReference> {
    Ok(OwnerReference {
        api_version: "batch/v1".into(),
        kind: "Job".into(),
        name: job.name_any(),
        uid: job
            .uid()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow!("SSH Job has no UID"))?,
        controller: Some(true),
        block_owner_deletion: Some(false),
    })
}
