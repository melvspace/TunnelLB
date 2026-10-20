use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::PostParams;

use super::{
    MAX_ATTEMPTS, Store, config_map_value, delete_params, delete_result, machine_labels,
    machine_state_name, resource_version, retryable_write, validate_id,
};
use crate::{
    allocation::Ledger,
    api::{Machine, Publication, ServiceRequest},
};

impl Store {
    pub async fn allocate(
        &self,
        machine: &Machine,
        request: &ServiceRequest,
        id: &str,
    ) -> Result<u16> {
        self.allocate_lease(machine, request, id, false).await
    }

    /// Recover a reservation committed before its publication record was saved.
    /// The controller must serialize this with record creation and first Apply.
    /// A present record, even unpublished or removing, always blocks replacement.
    pub async fn allocate_unpublished(
        &self,
        machine: &Machine,
        request: &ServiceRequest,
        id: &str,
    ) -> Result<u16> {
        self.allocate_lease(machine, request, id, true).await
    }

    /// Read local exclusions without reserving a second control port. The host
    /// arbitrates these numbers against reservations from other controllers.
    pub async fn control_exclusions(
        &self,
        machine: &Machine,
        publication: &Publication,
    ) -> Result<Vec<u16>> {
        validate_id(&publication.id)?;
        let labels = machine_labels("allocation", &publication.machine_uid)?;
        let name = machine_state_name("ports", &publication.machine_uid);
        let object = self
            .config_maps()
            .get_opt(&name)
            .await?
            .context("publication allocation ledger is missing")?;
        self.check_owned(&object.metadata, &name, &labels)?;
        resource_version(&object.metadata)?;
        read_ledger(&object)?.control_exclusions(machine, publication)
    }

    /// Persist a host-selected control using the publication's previous control
    /// as a precondition. A successful earlier confirmation is an idempotent retry.
    pub async fn confirm_control(
        &self,
        machine: &Machine,
        publication: &Publication,
        control_port: u16,
    ) -> Result<()> {
        validate_id(&publication.id)?;
        self.edit_ledger(&publication.machine_uid, false, None, |ledger| {
            ledger.confirm_control(machine, publication, control_port)
        })
        .await?
        .context("publication allocation ledger is missing")
    }

    async fn allocate_lease(
        &self,
        machine: &Machine,
        request: &ServiceRequest,
        id: &str,
        unpublished: bool,
    ) -> Result<u16> {
        validate_id(id)?;
        ensure!(!request.uid.is_empty(), "Service UID is required");
        let machine_uid = machine
            .metadata
            .uid
            .as_deref()
            .filter(|uid| !uid.is_empty())
            .context("Machine UID is required")?;
        self.edit_ledger(machine_uid, true, unpublished.then_some(id), |ledger| {
            if unpublished {
                ledger.allocate_unpublished(id, request, machine)
            } else {
                ledger.allocate(id, request, machine)
            }
        })
        .await?
        .context("allocation ledger was not created")
    }

    pub async fn release(&self, machine_uid: &str, id: &str) -> Result<()> {
        validate_id(id)?;
        self.edit_ledger(machine_uid, false, None, |ledger| {
            ledger.release(id);

            Ok(())
        })
        .await?;

        Ok(())
    }

    /// The caller must derive live IDs from all current Services, including
    /// allocations whose publication record was not saved before a crash.
    pub async fn gc_allocations(
        &self,
        machine_uid: &str,
        live_ids: &BTreeSet<String>,
    ) -> Result<()> {
        self.edit_ledger(machine_uid, false, None, |ledger| {
            for id in ledger.publication_ids() {
                if !live_ids.contains(&id) {
                    ledger.release(&id);
                }
            }

            Ok(())
        })
        .await?;

        Ok(())
    }

    pub async fn delete_ledger(&self, machine_uid: &str) -> Result<()> {
        let labels = machine_labels("allocation", machine_uid)?;
        let name = machine_state_name("ports", machine_uid);
        let api = self.config_maps();

        if let Some(object) = api.get_opt(&name).await? {
            self.check_owned(&object.metadata, &name, &labels)?;
            let ledger = read_ledger(&object)?;
            ensure!(
                ledger.is_empty(),
                "cannot delete a nonempty allocation ledger"
            );
            delete_result(api.delete(&name, &delete_params(&object.metadata)?).await)?;
        }

        Ok(())
    }

    async fn edit_ledger<T>(
        &self,
        machine_uid: &str,
        create: bool,
        unpublished_id: Option<&str>,
        edit: impl Fn(&mut Ledger) -> Result<T>,
    ) -> Result<Option<T>> {
        let labels = machine_labels("allocation", machine_uid)?;
        let name = machine_state_name("ports", machine_uid);
        let api = self.config_maps();

        for _ in 0..MAX_ATTEMPTS {
            if let Some(id) = unpublished_id {
                ensure!(
                    self.get_record(id).await?.is_none(),
                    "cannot replace a reservation with an existing publication record"
                );
            }

            let existing = api.get_opt(&name).await?;
            let (mut object, mut ledger, replacing) = match existing {
                Some(object) => {
                    self.check_owned(&object.metadata, &name, &labels)?;
                    resource_version(&object.metadata)?;
                    let ledger = read_ledger(&object)?;
                    (object, ledger, true)
                }

                None if create => (
                    ConfigMap {
                        metadata: self.metadata(&name, labels.clone()),
                        ..Default::default()
                    },
                    Ledger::default(),
                    false,
                ),
                None => return Ok(None),
            };
            // Reapply the edit to the freshly read ledger on *every* conflict.
            let value = edit(&mut ledger)?;
            let encoded =
                serde_json::to_string(&ledger).context("serializing allocation ledger")?;

            if replacing && config_map_value(&object, "ledger.json")? == encoded {
                return Ok(Some(value));
            }

            object
                .data
                .get_or_insert_default()
                .insert("ledger.json".into(), encoded);
            let result = if replacing {
                api.replace(&name, &PostParams::default(), &object).await
            } else {
                api.create(&PostParams::default(), &object).await
            };
            match result {
                Ok(_) => return Ok(Some(value)),
                Err(error) if retryable_write(&error, replacing) => continue,
                Err(error) => return Err(error.into()),
            }
        }

        bail!("allocation ledger remained contended after {MAX_ATTEMPTS} attempts")
    }
}

fn read_ledger(object: &ConfigMap) -> Result<Ledger> {
    serde_json::from_str(config_map_value(object, "ledger.json")?)
        .context("decoding allocation ledger")
}
