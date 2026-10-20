use super::{Allocation, Ledger, PortReservation, validate_id};
use crate::api::{Publication, Server};
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeSet, net::Ipv4Addr};

impl Ledger {
    /// Numbers unavailable to the host's control-port selection. The existing
    /// control is deliberately omitted unless current Server policy excludes it.
    pub(crate) fn control_exclusions(
        &self,
        server: &Server,
        publication: &Publication,
    ) -> Result<Vec<u16>> {
        let allocation = self.publication_allocation(server, publication)?;
        let range = server.spec.control_port_range;
        ensure!(
            range.start != 0 && range.start <= range.end,
            "control port range must be nonzero and ordered"
        );
        ensure!(
            server.spec.ssh.port != 0,
            "SSH port must be greater than zero"
        );
        let mut exclusions: BTreeSet<_> = server.spec.reserved_ports.iter().copied().collect();
        ensure!(
            !exclusions.contains(&0),
            "reserved ports must be greater than zero"
        );
        exclusions.insert(server.spec.ssh.port);
        ensure!(
            allocation
                .ports
                .iter()
                .all(|port| !exclusions.contains(&port.port)),
            "public ports conflict with SSH or administrator exclusions"
        );

        for (id, existing) in &self.allocations {
            exclusions.extend(&existing.reserved_ports);
            exclusions.extend(existing.ports.iter().map(|port| port.port));

            if id != &publication.id {
                exclusions.insert(existing.control_port);
            }
        }

        Ok(exclusions.into_iter().collect())
    }

    /// Commit the host-selected control without changing any other lease field.
    /// A retry may observe the selected control after the original CAS succeeded.
    pub(crate) fn confirm_control(
        &mut self,
        server: &Server,
        publication: &Publication,
        control_port: u16,
    ) -> Result<()> {
        let exclusions = self.control_exclusions(server, publication)?;
        let range = server.spec.control_port_range;
        ensure!(
            control_port != 0 && (range.start..=range.end).contains(&control_port),
            "selected TCP control port {control_port} is outside the Server range"
        );
        ensure!(
            !exclusions.contains(&control_port),
            "selected TCP control port {control_port} is already allocated or reserved"
        );
        let allocation = self
            .allocations
            .get_mut(&publication.id)
            .context("publication allocation is missing")?;
        ensure!(
            allocation.control_port == publication.control_port
                || allocation.control_port == control_port,
            "publication control port changed before confirmation"
        );
        allocation.control_port = control_port;

        Ok(())
    }

    fn publication_allocation(
        &self,
        server: &Server,
        publication: &Publication,
    ) -> Result<&Allocation> {
        validate_id("publication ID", &publication.id)?;
        self.validate()?;
        let allocation = self
            .allocations
            .get(&publication.id)
            .context("publication allocation is missing")?;
        let address: Ipv4Addr = server
            .spec
            .address
            .parse()
            .context("Server address must be IPv4")?;
        ensure!(
            Some(publication.server_name.as_str()) == server.metadata.name.as_deref()
                && Some(publication.server_uid.as_str()) == server.metadata.uid.as_deref()
                && publication.server_address == address,
            "publication does not match the Server identity or address"
        );
        let ports: BTreeSet<_> = publication
            .service
            .ports
            .iter()
            .map(|port| PortReservation {
                protocol: port.protocol,
                port: port.port,
            })
            .collect();
        ensure!(
            allocation.service_namespace == publication.service.namespace
                && allocation.service_name == publication.service.name
                && allocation.service_uid == publication.service.uid
                && allocation.server_name == publication.server_name
                && allocation.server_uid == publication.server_uid
                && allocation.server_address == publication.server_address
                && allocation.ports == ports
                && ports.len() == publication.service.ports.len(),
            "publication allocation has a different owner, Server or reservation set"
        );

        Ok(allocation)
    }
}
