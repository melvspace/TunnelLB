use crate::api::{FINALIZER, MANAGED_LABEL, PUBLICATION_LABEL};
use anyhow::{Result, ensure};
use kube::{
    Api, Resource, ResourceExt,
    api::{DeleteParams, Patch, PatchParams, PostParams, Preconditions, PropagationPolicy},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::fmt::Debug;

pub(super) fn has_finalizer<K: ResourceExt>(object: &K) -> bool {
    object.finalizers().iter().any(|f| f == FINALIZER)
}

pub(super) fn force_delete<K: ResourceExt>(object: &K) -> bool {
    object
        .annotations()
        .get("tunnellb.io/force-delete")
        .is_some_and(|v| v == "true")
}

pub(super) async fn set_finalizer<K>(api: &Api<K>, object: &K, add: bool) -> Result<()>
where
    K: Resource<DynamicType = ()> + Clone + Debug + DeserializeOwned + Serialize,
{
    let mut finalizers = object.finalizers().to_vec();
    finalizers.retain(|f| f != FINALIZER);

    if add {
        finalizers.push(FINALIZER.into());
    }

    if finalizers == object.finalizers() {
        return Ok(());
    }

    api.patch(
        &object.name_any(),
        &PatchParams::default(),
        &Patch::Merge(json!({
            "metadata": {"resourceVersion": object.resource_version(), "finalizers": finalizers}
        })),
    )
    .await?;
    Ok(())
}

/// Never adopt an object solely by a predictable name. UID-bound labels must
/// match before a field update, and resourceVersion protects concurrent writes.
pub(super) async fn apply_owned<K>(api: &Api<K>, wanted: &K) -> Result<()>
where
    K: Resource<DynamicType = ()> + Clone + Debug + DeserializeOwned + Serialize,
{
    if let Some(current) = api.get_opt(&wanted.name_any()).await? {
        ensure!(
            wanted
                .labels()
                .iter()
                .all(|(k, v)| current.labels().get(k) == Some(v)),
            "resource ownership conflict"
        );
        ensure!(
            current.meta().deletion_timestamp.is_none(),
            "resource deletion pending"
        );
        // Merge preserves server defaults and status; absent data keys are not
        // relied on for security (client Secret has a fixed schema).
        let mut patch = serde_json::to_value(wanted)?;
        patch["metadata"]["resourceVersion"] = json!(current.resource_version());
        let current_json = serde_json::to_value(&current)?;

        if contains_fields(&current_json, &patch) {
            return Ok(());
        }

        api.patch(
            &wanted.name_any(),
            &PatchParams::default(),
            &Patch::Merge(patch),
        )
        .await?;
    } else {
        api.create(&PostParams::default(), wanted).await?;
    }

    Ok(())
}

pub(super) fn contains_fields(actual: &Value, wanted: &Value) -> bool {
    match (actual, wanted) {
        (Value::Object(a), Value::Object(w)) => w
            .iter()
            .all(|(k, v)| a.get(k).is_some_and(|x| contains_fields(x, v))),
        (Value::Array(a), Value::Array(w)) => {
            a.len() == w.len() && a.iter().zip(w).all(|(a, w)| contains_fields(a, w))
        }

        _ => actual == wanted,
    }
}

pub(super) async fn delete_owned<K>(
    api: &Api<K>,
    name: &str,
    publication: Option<&str>,
) -> Result<()>
where
    K: Resource<DynamicType = ()> + Clone + Debug + DeserializeOwned,
{
    if let Some(object) = api.get_opt(name).await? {
        ensure!(
            object.labels().get(MANAGED_LABEL).map(String::as_str) == Some("tunnellb"),
            "resource ownership conflict"
        );

        if let Some(id) = publication {
            ensure!(
                object.labels().get(PUBLICATION_LABEL).map(String::as_str) == Some(id),
                "publication ownership conflict"
            );
        }

        if object.meta().deletion_timestamp.is_none() {
            let result = api
                .delete(
                    name,
                    &DeleteParams {
                        grace_period_seconds: Some(2),
                        propagation_policy: Some(PropagationPolicy::Foreground),
                        preconditions: Some(Preconditions {
                            uid: object.uid(),
                            resource_version: None,
                        }),
                        ..Default::default()
                    },
                )
                .await;
            match result {
                Err(kube::Error::Api(e)) if e.code == 404 => {}
                other => {
                    other?;
                }
            }
        }
    }

    Ok(())
}
