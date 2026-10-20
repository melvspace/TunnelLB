//! The host arbitrates shared ports; local state must commit its answer before Apply.
use anyhow::{Context as _, Result, ensure};

use crate::{
    api::Machine,
    jobs::{self, State},
    provision::{AllocationOutcome, Operation, ReservationRequest},
    store::{HostPin, PublicationRecord},
};

use super::{
    Context,
    machine::request_for,
    publication::{cleanup_publication, publication_hash},
};

#[derive(Debug, thiserror::Error)]
pub(super) enum ReservationConflict {
    #[error("Public port {0} is already reserved or listening on the shared host.")]
    Port(u16),
    #[error("No free tunnel control port remains in this Machine's controlPortRange.")]
    ControlRange,
}

impl ReservationConflict {
    pub(super) fn reason(&self) -> &'static str {
        match self {
            Self::Port(_) => "PortConflict",
            Self::ControlRange => "ControlPortsExhausted",
        }
    }
}

pub(super) async fn reserve_publication(
    record: &mut PublicationRecord,
    machine: &Machine,
    pin: &HostPin,
    generation: &str,
    context: &Context,
) -> Result<()> {
    let publication = &record.publication;
    let mut request = request_for(
        machine,
        Operation::Reserve,
        publication.machine_address,
        Some(pin),
    );
    request.publication = Some(publication.clone());
    request.generation = Some(generation.into());
    request.reservation = Some(ReservationRequest {
        control_port_range: machine.spec.control_port_range,
        excluded_ports: context
            .store
            .control_exclusions(machine, publication)
            .await?,
    });
    let revision = context.revision("reserve");
    let outcome = match jobs::run(
        &context.client,
        &context.resources,
        machine,
        &request,
        &revision,
    )
    .await?
    {
        State::Pending | State::Failed(_) => return Ok(()),
        State::Complete(outcome) => outcome,
    };

    match outcome
        .allocation
        .context("missing host reservation result")?
    {
        AllocationOutcome::Reserved { control_port } => {
            // Local leases can change while the SSH Job runs. Do not leave a
            // remote claim stranded if its chosen control has since been taken.
            let exclusions = context
                .store
                .control_exclusions(machine, &record.publication)
                .await?;

            if exclusions.contains(&control_port) {
                replace_reservation(record, context).await?;

                return Ok(());
            }

            commit_reservation(record, machine, control_port, context).await?;
        }
        AllocationOutcome::ReservationChanged => {
            replace_reservation(record, context).await?;
        }
        AllocationOutcome::PortConflict { port } => {
            return Err(ReservationConflict::Port(port).into());
        }
        AllocationOutcome::ControlRangeExhausted => {
            return Err(ReservationConflict::ControlRange.into());
        }
    }

    Ok(())
}

async fn replace_reservation(record: &PublicationRecord, context: &Context) -> Result<()> {
    ensure!(
        record.applied_hash.is_none() && !record.published,
        "cannot replace an applied host reservation"
    );
    cleanup_publication(record, context, false).await?;

    Ok(())
}

pub(super) async fn commit_reservation(
    record: &mut PublicationRecord,
    machine: &Machine,
    control_port: u16,
    context: &Context,
) -> Result<()> {
    ensure!(
        control_port == record.publication.control_port
            || (record.applied_hash.is_none() && !record.published),
        "cannot change the control port of an applied publication"
    );
    context
        .store
        .confirm_control(machine, &record.publication, control_port)
        .await?;
    record.publication.control_port = control_port;
    record.config_hash = publication_hash(&record.publication, &context.resources)?;
    record.reserved = true;
    context.store.save_record(record).await?;

    Ok(())
}
