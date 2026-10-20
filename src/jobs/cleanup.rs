//! Delete only verified request artifacts using the observed UID and resource version.

use std::fmt::Debug;

use anyhow::{Result, anyhow};
use k8s_openapi::{
    api::{batch::v1::Job, core::v1::Secret, networking::v1::NetworkPolicy},
    apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference},
};
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{DeleteParams, ListParams, Preconditions},
};
use serde::de::DeserializeOwned;

use super::{
    identity::{Identity, JOB_UID, KIND_LABEL},
    runtime::{api_error, get},
};
use crate::api::MANAGED_LABEL;

/// Delete only this module's artifacts selected by the caller's Machine/publication scope.
pub async fn cleanup(client: &Client, namespace: &str, selector: &str) -> Result<()> {
    let selector = if selector.is_empty() {
        format!("{MANAGED_LABEL}=tunnellb,{KIND_LABEL}=ssh-job")
    } else {
        format!("{selector},{MANAGED_LABEL}=tunnellb,{KIND_LABEL}=ssh-job")
    };

    let params = ListParams::default().labels(&selector);
    let jobs: Api<Job> = Api::namespaced(client.clone(), namespace);
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let policies: Api<NetworkPolicy> = Api::namespaced(client.clone(), namespace);
    let listed_jobs = jobs
        .list(&params)
        .await
        .map_err(|e| api_error("list SSH Jobs", e))?;
    let listed_secrets = secrets
        .list(&params)
        .await
        .map_err(|e| api_error("list SSH request Secrets", e))?;
    let listed_policies = policies
        .list(&params)
        .await
        .map_err(|e| api_error("list SSH NetworkPolicies", e))?;
    for job in listed_jobs {
        let Some(identity) = Identity::from_metadata(&job.metadata, namespace) else {
            continue;
        };

        if identity.verify(&job.metadata, None).is_ok() {
            delete_owned(&jobs, &job).await?;
        }
    }

    for secret in listed_secrets {
        // A credential/pin/connector Secret can never qualify by labels alone.

        if secret.immutable != Some(true)
            || secret.type_.as_deref() != Some("Opaque")
            || !secret
                .data
                .as_ref()
                .is_some_and(|data| data.len() == 1 && data.contains_key("request.json"))
        {
            continue;
        }

        if owned_dependent(&jobs, &secret.metadata, namespace).await? {
            delete_owned(&secrets, &secret).await?;
        }
    }

    for policy in listed_policies {
        if owned_dependent(&jobs, &policy.metadata, namespace).await? {
            delete_owned(&policies, &policy).await?;
        }
    }

    Ok(())
}

async fn owned_dependent(jobs: &Api<Job>, metadata: &ObjectMeta, namespace: &str) -> Result<bool> {
    let Some(identity) = Identity::from_metadata(metadata, namespace) else {
        return Ok(false);
    };

    if identity.verify(metadata, None).is_ok() {
        return Ok(true);
    }

    let Some(uid) = metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(JOB_UID))
        .filter(|u| !u.is_empty())
    else {
        return Ok(false);
    };

    let owner = OwnerReference {
        api_version: "batch/v1".into(),
        kind: "Job".into(),
        name: identity.name.clone(),
        uid: uid.clone(),
        controller: Some(true),
        block_owner_deletion: Some(false),
    };

    if identity.verify(metadata, Some(&owner)).is_err() {
        return Ok(false);
    }

    if let Some(job) = get(jobs, &identity.name).await? {
        return Ok(
            job.uid().as_deref() == Some(uid) && identity.verify(&job.metadata, None).is_ok()
        );
    }

    Ok(true)
}

async fn delete_owned<K>(api: &Api<K>, resource: &K) -> Result<()>
where
    K: Clone + DeserializeOwned + Debug + Resource<DynamicType = ()>,
{
    let uid = resource
        .uid()
        .ok_or_else(|| anyhow!("SSH artifact has no UID"))?;
    let version = resource
        .resource_version()
        .ok_or_else(|| anyhow!("SSH artifact has no resource version"))?;
    let params = DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(uid),
            resource_version: Some(version),
        }),
        ..DeleteParams::background()
    };

    match api.delete(&resource.name_any(), &params).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(response)) if response.code == 404 => Ok(()),
        Err(error) => Err(api_error("delete SSH artifact", error)),
    }
}
