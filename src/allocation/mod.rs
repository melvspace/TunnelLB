//! In-memory reservations; the controller persists the complete ledger using CAS.
//!
//! A compatible retry has the same Service namespace/name/UID, Machine name/UID
//! and IPv4 address, and exact set of public `(protocol, port)` pairs. It retains
//! its control port, which must still satisfy the current Machine policy.
//! Backend, port-name, PROXY protocol and selection metadata do not own sockets
//! and may change without reallocating. Changing ownership, address or public
//! reservations requires explicit release after the old publication is stopped.
//!
//! FRP's allowPorts authorizes numbers without a protocol qualifier. Different
//! publications therefore cannot share any public/control port number on the
//! same Machine/address. One publication may expose TCP and UDP on the same
//! number, but its control port must be distinct from all of its public ports.

mod control;

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::api::{Machine, Protocol, ServiceRequest};

/// Expected capacity failures for which a caller may try another Machine.
/// Validation, ownership and persistence failures deliberately do not use this type.
#[derive(Debug, thiserror::Error)]
pub enum AllocationConflict {
    #[error(
        "public port {port} is already allocated or reserved on this Machine/address regardless of protocol"
    )]
    PortUnavailable { port: u16 },
    #[error("SSH or administrator exclusions conflict with allocation {publication_id}")]
    ReservedPorts { publication_id: String },
    #[error("no TCP control ports available in the Machine range")]
    ControlRangeExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PortReservation {
    pub protocol: Protocol,
    pub port: u16,
}

/// Socket ownership, independent of the Service's mutable forwarding metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Allocation {
    pub service_namespace: String,
    pub service_name: String,
    pub service_uid: String,
    pub machine_name: String,
    pub machine_uid: String,
    pub machine_address: Ipv4Addr,
    pub ports: BTreeSet<PortReservation>,
    pub control_port: u16,
    /// SSH and administrator-reserved ports, protected for both protocols.
    ///
    /// Keeping this snapshot prevents another Machine object for the same host
    /// from bypassing these exclusions. A compatible retry refreshes its snapshot;
    /// other live allocations keep their exclusions until refreshed or released.
    pub reserved_ports: BTreeSet<u16>,
}

impl Allocation {
    fn same_owner(&self, requested: &Self) -> bool {
        self.service_namespace == requested.service_namespace
            && self.service_name == requested.service_name
            && self.service_uid == requested.service_uid
            && self.machine_name == requested.machine_name
            && self.machine_uid == requested.machine_uid
    }

    fn compatible_with(&self, requested: &Self) -> bool {
        self.same_owner(requested)
            && self.machine_address == requested.machine_address
            && self.ports == requested.ports
    }

    fn shares_machine_with(&self, other: &Self) -> bool {
        // A recreated object or an address alias must not hide an old lease.
        self.machine_name == other.machine_name
            || self.machine_uid == other.machine_uid
            || self.machine_address == other.machine_address
    }

    fn validate(&self) -> Result<()> {
        for (kind, value) in [
            ("Service namespace", self.service_namespace.as_str()),
            ("Service name", self.service_name.as_str()),
            ("Service UID", self.service_uid.as_str()),
            ("Machine name", self.machine_name.as_str()),
            ("Machine UID", self.machine_uid.as_str()),
        ] {
            validate_id(kind, value)?;
        }

        ensure!(
            !self.ports.is_empty(),
            "a publication must reserve public ports"
        );
        ensure!(
            self.control_port != 0,
            "a TCP control port must be greater than zero"
        );
        ensure!(
            !self.reserved_ports.contains(&0),
            "reserved ports must be greater than zero"
        );
        ensure!(
            !self.reserved_ports.contains(&self.control_port),
            "TCP control port {} is reserved for SSH or administration",
            self.control_port
        );

        for reservation in &self.ports {
            ensure!(
                reservation.port != 0,
                "public ports must be greater than zero"
            );
            ensure!(
                !self.reserved_ports.contains(&reservation.port),
                "public port {} is reserved for SSH or administration",
                reservation.port
            );
            ensure!(
                reservation.port != self.control_port,
                "public port {} conflicts with the TCP control port",
                reservation.port
            );
        }

        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    pub allocations: BTreeMap<String, Allocation>,
}

impl Ledger {
    /// Reserve every public port number and one distinct TCP control port, or
    /// change nothing. Protocols remain part of a lease's exact retry identity,
    /// but never permit different publications to share a port number.
    ///
    /// Control ports are chosen in ascending order. A compatible allocation keeps
    /// its existing control port, even if a lower port has since become available.
    /// Within this ledger, conflicts are checked by Machine name, UID or address.
    /// Callers using separate ledgers must arbitrate reservations on the shared
    /// host and persist each result with optimistic concurrency before use.
    pub fn allocate(
        &mut self,
        publication_id: &str,
        service: &ServiceRequest,
        machine: &Machine,
    ) -> Result<u16> {
        validate_id("publication ID", publication_id)?;
        let machine_name = machine
            .metadata
            .name
            .as_deref()
            .context("Machine name is required")?;
        let machine_uid = machine
            .metadata
            .uid
            .as_deref()
            .context("Machine UID is required")?;

        for (kind, value) in [
            ("Service namespace", service.namespace.as_str()),
            ("Service name", service.name.as_str()),
            ("Service UID", service.uid.as_str()),
            ("Machine name", machine_name),
            ("Machine UID", machine_uid),
        ] {
            validate_id(kind, value)?;
        }

        let range = machine.spec.control_port_range;
        ensure!(
            range.start != 0 && range.start <= range.end,
            "control port range must be nonzero and ordered"
        );
        ensure!(
            machine.spec.ssh.port != 0,
            "SSH port must be greater than zero"
        );
        let mut reserved_ports: BTreeSet<_> = machine.spec.reserved_ports.iter().copied().collect();
        ensure!(
            !reserved_ports.contains(&0),
            "reserved ports must be greater than zero"
        );
        reserved_ports.insert(machine.spec.ssh.port);

        ensure!(
            !service.ports.is_empty(),
            "a publication must reserve public ports"
        );
        let mut ports = BTreeSet::new();

        for port in &service.ports {
            ensure!(port.port != 0, "public ports must be greater than zero");
            ensure!(
                ports.insert(PortReservation {
                    protocol: port.protocol,
                    port: port.port
                }),
                "duplicate public {}/{} reservation",
                port.protocol.as_str(),
                port.port
            );
        }

        let mut requested = Allocation {
            service_namespace: service.namespace.clone(),
            service_name: service.name.clone(),
            service_uid: service.uid.clone(),
            machine_name: machine_name.to_owned(),
            machine_uid: machine_uid.to_owned(),
            machine_address: machine
                .spec
                .address
                .parse()
                .context("Machine address must be IPv4")?,
            ports,
            control_port: 0,
            reserved_ports,
        };
        // A capacity error permits assignment elsewhere. Validate every stored
        // lease first, so corruption cannot be mistaken for an unavailable edge.
        self.validate()?;
        let mut next = self.clone();
        let existing_control = if let Some(existing) = next.allocations.get(publication_id) {
            ensure!(
                existing.compatible_with(&requested),
                "publication {publication_id} already has a different owner, Machine or reservation set"
            );
            Some(existing.control_port)
        } else {
            None
        };

        let mut occupied = BTreeSet::new();
        let mut excluded = requested.reserved_ports.clone();

        for (id, existing) in &next.allocations {
            if id == publication_id || !existing.shares_machine_with(&requested) {
                continue;
            }

            ensure!(
                !requested.reserved_ports.contains(&existing.control_port)
                    && existing
                        .ports
                        .iter()
                        .all(|p| !requested.reserved_ports.contains(&p.port)),
                AllocationConflict::ReservedPorts {
                    publication_id: id.clone()
                }
            );
            occupied.extend(existing.ports.iter().map(|p| p.port));
            occupied.insert(existing.control_port);
            excluded.extend(&existing.reserved_ports);
        }

        for port in &requested.ports {
            ensure!(
                !occupied.contains(&port.port) && !excluded.contains(&port.port),
                AllocationConflict::PortUnavailable { port: port.port }
            );
        }

        // Check other owners first, then include our own public numbers. This
        // allows TCP+UDP within one publication while keeping control distinct.
        occupied.extend(requested.ports.iter().map(|p| p.port));
        let control_available = |port| !excluded.contains(&port) && !occupied.contains(&port);
        requested.control_port = match existing_control {
            Some(port) => {
                ensure!(
                    (range.start..=range.end).contains(&port) && control_available(port),
                    "existing TCP control port {port} is outside the range or no longer available"
                );
                port
            }

            None => (range.start..=range.end)
                .find(|&port| control_available(port))
                .ok_or(AllocationConflict::ControlRangeExhausted)?,
        };
        requested.validate()?;
        let control_port = requested.control_port;
        next.allocations
            .insert(publication_id.to_owned(), requested);
        *self = next;

        Ok(control_port)
    }

    /// Replace only a reservation with no publication record. The store checks
    /// record absence under controller serialization before committing this edit.
    pub(crate) fn allocate_unpublished(
        &mut self,
        publication_id: &str,
        service: &ServiceRequest,
        machine: &Machine,
    ) -> Result<u16> {
        // Releasing first must not erase evidence of malformed or foreign state.
        self.validate()?;

        if let Some(existing) = self.allocations.get(publication_id) {
            ensure!(
                existing.service_namespace == service.namespace
                    && existing.service_name == service.name
                    && existing.service_uid == service.uid
                    && Some(existing.machine_name.as_str()) == machine.metadata.name.as_deref()
                    && Some(existing.machine_uid.as_str()) == machine.metadata.uid.as_deref(),
                "unpublished reservation ownership cannot change"
            );
        }

        let mut replacement = self.clone();
        replacement.release(publication_id);
        let port = replacement.allocate(publication_id, service, machine)?;
        *self = replacement;

        Ok(port)
    }

    fn validate(&self) -> Result<()> {
        // Validate all rows before considering cross-row conflicts. Scope by all
        // three identities used by shares_machine_with, with numeric port sets
        // matching FRP's authorization semantics.
        for (id, allocation) in &self.allocations {
            validate_id("stored publication ID", id)?;
            allocation
                .validate()
                .with_context(|| format!("invalid allocation {id}"))?;
        }

        let mut scopes = BTreeMap::<String, (BTreeSet<u16>, BTreeSet<u16>)>::new();

        for (id, allocation) in &self.allocations {
            let mut ports: BTreeSet<_> = allocation.ports.iter().map(|p| p.port).collect();
            ports.insert(allocation.control_port);

            for identity in [
                format!("name:{}", allocation.machine_name),
                format!("uid:{}", allocation.machine_uid),
                format!("address:{}", allocation.machine_address),
            ] {
                let (occupied, reserved) = scopes.entry(identity).or_default();
                ensure!(
                    ports.is_disjoint(occupied)
                        && ports.is_disjoint(reserved)
                        && allocation.reserved_ports.is_disjoint(occupied),
                    "invalid allocation ledger: overlapping stored reservation {id}"
                );
                occupied.extend(&ports);
                reserved.extend(&allocation.reserved_ports);
            }
        }

        Ok(())
    }

    /// Forget a reservation after revocation/cleanup; absent IDs are a no-op.
    pub fn release(&mut self, id: &str) {
        self.allocations.remove(id);
    }

    /// Stable ordering makes orphan collection deterministic.
    pub fn publication_ids(&self) -> Vec<String> {
        self.allocations.keys().cloned().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.allocations.is_empty()
    }
}

fn validate_id(kind: &str, value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && !value.chars().any(|c| c.is_whitespace() || c.is_control()),
        "{kind} must be nonempty and contain no whitespace or control characters"
    );

    Ok(())
}

#[cfg(test)]
mod tests;
