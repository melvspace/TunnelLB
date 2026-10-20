use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use k8s_openapi::{
    api::networking::v1::{
        IPBlock, NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyPeer, NetworkPolicyPort,
        NetworkPolicySpec,
    },
    apimachinery::pkg::util::intstr::IntOrString,
};

use crate::api::{BackendPort, Protocol, Publication};

use super::{ResourceOptions, metadata, publication_labels, selector, ssh_labels};

/// Deny ingress and allow only the edge control connection and resolved backends.
pub fn connector_policy(
    publication: &Publication,
    backend_ports: &[BackendPort],
    options: &ResourceOptions,
) -> NetworkPolicy {
    let mut egress = vec![edge_rule(
        publication.machine_address,
        publication.control_port,
    )];

    if !publication.service.selector.is_empty() && !backend_ports.is_empty() {
        let ports = backend_ports
            .iter()
            .map(|backend| (backend.protocol, backend.port))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|(protocol, port)| policy_port(protocol, port))
            .collect();

        egress.push(NetworkPolicyEgressRule {
            ports: Some(ports),
            to: Some(vec![NetworkPolicyPeer {
                // Both selectors must be in the SAME peer: separate peers would
                // allow every pod in the namespace OR matching local pods.
                namespace_selector: Some(selector(BTreeMap::from([(
                    "kubernetes.io/metadata.name".into(),
                    publication.service.namespace.clone(),
                )]))),
                pod_selector: Some(selector(publication.service.selector.clone())),
                ..Default::default()
            }]),
        });
    }

    policy(
        &publication.id,
        publication_labels(publication),
        egress,
        options,
    )
}

pub fn ssh_policy(
    name: &str,
    address: Ipv4Addr,
    ssh_port: u16,
    options: &ResourceOptions,
) -> NetworkPolicy {
    policy(
        name,
        ssh_labels(name),
        vec![edge_rule(address, ssh_port)],
        options,
    )
}

fn policy(
    name: &str,
    labels: BTreeMap<String, String>,
    egress: Vec<NetworkPolicyEgressRule>,
    options: &ResourceOptions,
) -> NetworkPolicy {
    NetworkPolicy {
        metadata: metadata(name, labels.clone(), options),
        spec: Some(NetworkPolicySpec {
            pod_selector: Some(selector(labels)),
            policy_types: Some(vec!["Ingress".into(), "Egress".into()]),
            ingress: Some(vec![]),
            egress: Some(egress),
        }),
    }
}

fn policy_port(protocol: Protocol, port: u16) -> NetworkPolicyPort {
    NetworkPolicyPort {
        protocol: Some(protocol.as_str().into()),
        port: Some(IntOrString::Int(i32::from(port))),
        ..Default::default()
    }
}

fn edge_rule(address: Ipv4Addr, port: u16) -> NetworkPolicyEgressRule {
    NetworkPolicyEgressRule {
        to: Some(vec![NetworkPolicyPeer {
            ip_block: Some(IPBlock {
                cidr: format!("{address}/32"),
                ..Default::default()
            }),
            ..Default::default()
        }]),
        ports: Some(vec![policy_port(Protocol::Tcp, port)]),
    }
}
