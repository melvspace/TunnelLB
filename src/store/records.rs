use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{ListParams, PostParams};
use serde::{Deserialize, Serialize};

use super::{
    KIND_LABEL, MAX_ATTEMPTS, Store, config_map_value, delete_params, delete_result,
    publication_labels, resource_version, retryable_write, validate_id,
};
use crate::api::{BackendPort, MANAGED_LABEL, Publication, ServerSpec};

/// Desired/applied publication state. Credentials are stored separately.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationRecord {
    pub publication: Publication,
    pub server_spec: ServerSpec,
    pub backend_ports: Vec<BackendPort>,
    pub config_hash: String,
    pub applied_hash: Option<String>,
    pub published: bool,
    #[serde(default)]
    pub reserved: bool,
    #[serde(default)]
    pub removing: bool,
    #[serde(default)]
    pub credential_generation: Option<String>,
}

impl Store {
    pub async fn records(&self, label_selector: &str) -> Result<Vec<PublicationRecord>> {
        let mut selector = format!("{MANAGED_LABEL}=tunnellb,{KIND_LABEL}=publication");

        if !label_selector.is_empty() {
            selector.push(',');
            selector.push_str(label_selector);
        }

        self.config_maps()
            .list(&ListParams::default().labels(&selector))
            .await?
            .items
            .iter()
            .map(|object| self.read_record(object, None))
            .collect()
    }

    pub async fn get_record(&self, id: &str) -> Result<Option<PublicationRecord>> {
        validate_id(id)?;
        self.config_maps()
            .get_opt(id)
            .await?
            .map(|object| self.read_record(&object, Some(id)))
            .transpose()
    }

    pub async fn save_record(&self, record: &PublicationRecord) -> Result<()> {
        let labels = publication_labels("publication", &record.publication)?;
        let id = &record.publication.id;
        let encoded = serde_json::to_string(record).context("serializing publication record")?;
        let api = self.config_maps();

        for _ in 0..MAX_ATTEMPTS {
            let existing = api.get_opt(id).await?;
            let replacing = existing.is_some();
            let result = match existing {
                Some(mut object) => {
                    let previous = self.read_record(&object, Some(id))?;
                    ensure_same_publication_owner(&previous.publication, &record.publication)?;
                    resource_version(&object.metadata)?;

                    if config_map_value(&object, "record.json")? == encoded {
                        return Ok(());
                    }

                    object
                        .data
                        .get_or_insert_default()
                        .insert("record.json".into(), encoded.clone());
                    api.replace(id, &PostParams::default(), &object).await
                }

                None => {
                    let object = ConfigMap {
                        metadata: self.metadata(id, labels.clone()),
                        data: Some(BTreeMap::from([("record.json".into(), encoded.clone())])),
                        ..Default::default()
                    };
                    api.create(&PostParams::default(), &object).await
                }
            };
            match result {
                Ok(_) => return Ok(()),
                Err(error) if retryable_write(&error, replacing) => continue,
                Err(error) => return Err(error.into()),
            }
        }

        bail!("publication record remained contended after {MAX_ATTEMPTS} attempts")
    }

    pub async fn delete_record(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        let api = self.config_maps();

        if let Some(object) = api.get_opt(id).await? {
            self.read_record(&object, Some(id))?;
            delete_result(api.delete(id, &delete_params(&object.metadata)?).await)?;
        }

        Ok(())
    }

    fn read_record(&self, object: &ConfigMap, id: Option<&str>) -> Result<PublicationRecord> {
        let record: PublicationRecord =
            serde_json::from_str(config_map_value(object, "record.json")?)
                .context("decoding publication record")?;

        if let Some(id) = id {
            ensure!(
                record.publication.id == id,
                "publication record ID does not match"
            );
        }

        let labels = publication_labels("publication", &record.publication)?;
        self.check_owned(&object.metadata, &record.publication.id, &labels)?;

        Ok(record)
    }
}

fn ensure_same_publication_owner(previous: &Publication, next: &Publication) -> Result<()> {
    ensure!(
        previous.id == next.id
            && previous.server_uid == next.server_uid
            && previous.server_name == next.server_name
            && previous.service.uid == next.service.uid
            && previous.service.name == next.service.name
            && previous.service.namespace == next.service.namespace,
        "publication ownership cannot change"
    );

    Ok(())
}
