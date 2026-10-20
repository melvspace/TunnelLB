//! Reconcile in preflight/create/attach order with guarded, credential-safe API calls.

use std::fmt::Debug;

use anyhow::{Result, anyhow, ensure};
use k8s_openapi::{
    api::{
        batch::v1::Job,
        core::v1::{Pod, Secret},
        networking::v1::NetworkPolicy,
    },
    apimachinery::pkg::apis::meta::v1::OwnerReference,
};
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{ListParams, Patch, PatchParams, PostParams},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;

use super::{
    State,
    artifacts::{Artifacts, verify_job, verify_policy, verify_secret},
    identity::{Identity, JOB_UID, KIND_LABEL, job_reference},
    outcome::{Phase, phase, result},
};
use crate::{api, provision, resources};

/// Advance an operation once. Kubernetes owns execution, retries, and deadlines.
pub async fn run(
    client: &Client,
    options: &resources::ResourceOptions,
    server: &api::Server,
    request: &provision::Request,
    revision: &str,
) -> Result<State> {
    let Artifacts {
        identity,
        job: wanted_job,
        secret: wanted_secret,
        policy: wanted_policy,
    } = Artifacts::new(options, server, request, revision)?;

    let jobs: Api<Job> = Api::namespaced(client.clone(), &options.namespace);
    let secrets: Api<Secret> = Api::namespaced(client.clone(), &options.namespace);
    let policies: Api<NetworkPolicy> = Api::namespaced(client.clone(), &options.namespace);
    // Preflight every existing artifact before making any change.
    let existing_job = get(&jobs, &identity.name).await?;
    let existing_secret = get(&secrets, &identity.name).await?;
    let existing_policy = get(&policies, &identity.name).await?;
    let job_owner = existing_job.as_ref().map(job_reference).transpose()?;

    if let Some(job) = &existing_job {
        verify_job(job, &wanted_job, &identity)?;
    }

    if let Some(secret) = &existing_secret {
        verify_secret(secret, &wanted_secret, &identity, job_owner.as_ref())?;
    }

    if let Some(policy) = &existing_policy {
        verify_policy(policy, &wanted_policy, &identity, job_owner.as_ref())?;
    }

    if [
        &existing_job.as_ref().map(|v| &v.metadata),
        &existing_secret.as_ref().map(|v| &v.metadata),
        &existing_policy.as_ref().map(|v| &v.metadata),
    ]
    .iter()
    .any(|m| m.is_some_and(|m| m.deletion_timestamp.is_some()))
    {
        return Ok(State::Pending);
    }

    if existing_job.is_none() && server_has_pending_job(&jobs, &identity).await? {
        return Ok(State::Pending);
    }

    let secret = create_if_absent(&secrets, &wanted_secret, existing_secret).await?;
    verify_secret(&secret, &wanted_secret, &identity, job_owner.as_ref())?;
    let policy = create_if_absent(&policies, &wanted_policy, existing_policy).await?;
    verify_policy(&policy, &wanted_policy, &identity, job_owner.as_ref())?;
    // The egress policy and immutable request exist before a Pod can start.
    let job = create_if_absent(&jobs, &wanted_job, existing_job).await?;
    verify_job(&job, &wanted_job, &identity)?;
    let owner = job_reference(&job)?;
    attach_to_job(&secrets, secret, &identity, &owner, |secret| {
        verify_secret(secret, &wanted_secret, &identity, Some(&owner))
    })
    .await?;
    attach_to_job(&policies, policy, &identity, &owner, |policy| {
        verify_policy(policy, &wanted_policy, &identity, Some(&owner))
    })
    .await?;

    if phase(&job) == Phase::Pending {
        return Ok(State::Pending);
    }

    let pods: Api<Pod> = Api::namespaced(client.clone(), &options.namespace);
    let mut candidates = Vec::new();
    for label in ["batch.kubernetes.io/job-name", "job-name"] {
        let list = pods
            .list(&ListParams::default().labels(&format!("{label}={}", identity.name)))
            .await
            .map_err(|e| api_error("list SSH worker Pods", e))?;
        for pod in list {
            if !candidates.iter().any(|p: &Pod| p.uid() == pod.uid()) {
                candidates.push(pod);
            }
        }
    }

    Ok(result(request, &job, &candidates))
}

/// A pending Job blocks new requests for this Server incarnation across
/// publications and revisions. Existing desired Jobs must still be polled.
async fn server_has_pending_job(jobs: &Api<Job>, identity: &Identity) -> Result<bool> {
    let selector = format!(
        "{}=tunnellb,{KIND_LABEL}=ssh-job,{}={}",
        api::MANAGED_LABEL,
        api::SERVER_LABEL,
        identity.server
    );
    let listed = jobs
        .list(&ListParams::default().labels(&selector))
        .await
        .map_err(|error| api_error("list SSH Jobs", error))?;

    Ok(listed.items.iter().any(|job| {
        let Some(candidate) = Identity::from_metadata(&job.metadata, &identity.namespace) else {
            return false;
        };

        candidate.server == identity.server
            && candidate.server_uid == identity.server_uid
            && candidate.verify(&job.metadata, None).is_ok()
            && phase(job) == Phase::Pending
    }))
}

// Do not retain the original error as an anyhow source: admission errors can
// contain the submitted Secret, and transport/parser errors can include bodies.
pub(super) fn api_error(action: &str, error: kube::Error) -> anyhow::Error {
    match error {
        kube::Error::Api(response) => {
            anyhow!("{action} failed (Kubernetes HTTP {})", response.code)
        }

        _ => anyhow!("{action} failed (Kubernetes transport error)"),
    }
}

pub(super) async fn get<K>(api: &Api<K>, name: &str) -> Result<Option<K>>
where
    K: Clone + DeserializeOwned + Debug,
{
    api.get_opt(name)
        .await
        .map_err(|e| api_error("read SSH artifact", e))
}

async fn create_if_absent<K>(api: &Api<K>, desired: &K, existing: Option<K>) -> Result<K>
where
    K: Clone + DeserializeOwned + Serialize + Debug + Resource<DynamicType = ()>,
{
    if let Some(existing) = existing {
        return Ok(existing);
    }

    match api.create(&PostParams::default(), desired).await {
        Ok(created) => Ok(created),
        Err(kube::Error::Api(response)) if response.code == 409 => get(api, &desired.name_any())
            .await?
            .ok_or_else(|| anyhow!("SSH artifact disappeared after a creation conflict")),
        Err(error) => Err(api_error("create SSH artifact", error)),
    }
}

pub(super) async fn attach_to_job<K>(
    api: &Api<K>,
    mut artifact: K,
    id: &Identity,
    job: &OwnerReference,
    verify: impl Fn(&K) -> Result<()>,
) -> Result<()>
where
    K: Clone + DeserializeOwned + Serialize + Debug + Resource<DynamicType = ()>,
{
    for _ in 0..3 {
        verify(&artifact)?;
        ensure!(
            artifact.meta().deletion_timestamp.is_none(),
            "SSH artifact is being deleted"
        );

        if artifact
            .meta()
            .annotations
            .as_ref()
            .and_then(|a| a.get(JOB_UID))
            == Some(&job.uid)
        {
            return Ok(());
        }

        let uid = artifact
            .uid()
            .ok_or_else(|| anyhow!("SSH artifact has no UID"))?;
        let version = artifact
            .resource_version()
            .ok_or_else(|| anyhow!("SSH artifact has no resource version"))?;
        let patch = json!({"metadata": {
            "uid": uid, "resourceVersion": version,
            "ownerReferences": [job], "annotations": { JOB_UID: job.uid }
        }});
        match api
            .patch(&id.name, &PatchParams::default(), &Patch::Merge(patch))
            .await
        {
            Ok(updated) => {
                verify(&updated)?;
                ensure!(
                    updated
                        .meta()
                        .annotations
                        .as_ref()
                        .and_then(|a| a.get(JOB_UID))
                        == Some(&job.uid),
                    "SSH artifact Job owner was not recorded"
                );

                return Ok(());
            }

            Err(kube::Error::Api(response)) if response.code == 409 => {
                let updated = get(api, &id.name).await?.ok_or_else(|| {
                    anyhow!("SSH artifact disappeared while setting its Job owner")
                })?;
                ensure!(
                    updated.uid().as_deref() == Some(&uid),
                    "SSH artifact changed identity"
                );
                artifact = updated;
            }

            Err(error) => return Err(api_error("set SSH artifact Job owner", error)),
        }
    }

    Err(anyhow!(
        "SSH artifact ownership changed concurrently; retry reconciliation"
    ))
}
