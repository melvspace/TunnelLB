use std::{collections::BTreeSet, net::Ipv4Addr};

use anyhow::Result;
use k8s_openapi::api::core::v1::Node;

use crate::api::Machine;

use super::{
    ValidationError,
    primitives::{dns_label, dns_subdomain, parse_ipv4_or_mapped},
};

#[cfg(test)]
mod tests;

fn machine_error(message: impl Into<String>) -> anyhow::Error {
    ValidationError::InvalidMachine(message.into()).into()
}

/// `allow_private` is an explicit test-environment option, not permission to use
/// a Kubernetes Node. The caller must supply the complete current Node list.
pub fn validate_machine(
    machine: &Machine,
    nodes: &[Node],
    allow_private: bool,
) -> Result<Ipv4Addr> {
    let spec = &machine.spec;
    let address: Ipv4Addr = spec
        .address
        .parse()
        .map_err(|_| machine_error("spec.address must be a literal IPv4 address"))?;

    for node in nodes {
        for node_address in node
            .status
            .iter()
            .flat_map(|s| s.addresses.iter().flatten())
        {
            if parse_ipv4_or_mapped(&node_address.address) == Some(address) {
                return Err(machine_error(format!(
                    "address {address} belongs to Kubernetes Node {}",
                    node.metadata.name.as_deref().unwrap_or("<unnamed>")
                )));
            }
        }
    }

    if !ordinary_ipv4(address) || (address.is_private() && !allow_private) {
        return Err(machine_error(format!(
            "address {address} must be a public unicast IPv4 address; only RFC1918 addresses may be allowed in private test mode"
        )));
    }

    let user = spec.ssh.user.as_bytes();

    if user.is_empty()
        || user.len() > 32
        || !(user[0].is_ascii_alphabetic() || user[0] == b'_')
        || !user
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
    {
        return Err(machine_error(
            "ssh.user must be 1–32 ASCII letters, digits, underscores or hyphens, starting with a letter or underscore",
        ));
    }

    if spec.ssh.port == 0 {
        return Err(machine_error("ssh.port must be in 1..=65535"));
    }

    let secret = &spec.ssh.private_key_secret_ref;

    if !dns_subdomain(&secret.name) {
        return Err(machine_error(
            "ssh.privateKeySecretRef.name must be a DNS subdomain name",
        ));
    }

    if secret.key.is_empty()
        || secret.key.len() > 253
        || secret.key == "."
        || secret.key.starts_with("..")
        || !secret
            .key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
    {
        return Err(machine_error(
            "ssh.privateKeySecretRef.key must be a safe, nonempty Secret data key (letters, digits, '.', '_' or '-')",
        ));
    }

    let range = spec.control_port_range;

    if range.start == 0 || range.start > range.end {
        return Err(machine_error(
            "controlPortRange must satisfy 1 <= start <= end <= 65535",
        ));
    }

    let mut reserved = BTreeSet::new();

    for port in &spec.reserved_ports {
        if *port == 0 || !reserved.insert(*port) {
            return Err(machine_error(
                "reservedPorts must contain unique ports in 1..=65535",
            ));
        }
    }

    if !(range.start..=range.end).any(|p| p != spec.ssh.port && !reserved.contains(&p)) {
        return Err(machine_error(
            "controlPortRange contains no port outside SSH and reservedPorts",
        ));
    }

    if spec.pool.as_ref().is_some_and(|p| !dns_label(p)) {
        return Err(machine_error("pool must be a nonempty DNS label"));
    }

    let mut namespaces = BTreeSet::new();

    for namespace in &spec.allowed_namespaces {
        if !dns_label(namespace) || !namespaces.insert(namespace) {
            return Err(machine_error(
                "allowedNamespaces must contain unique DNS namespace names",
            ));
        }
    }

    Ok(address)
}

/// Private test mode admits RFC1918 but still excludes shared, documentation,
/// benchmarking, link-local and non-unicast addresses.
fn ordinary_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();

    !(a == 0
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}
