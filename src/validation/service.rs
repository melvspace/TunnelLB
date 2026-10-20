use std::{collections::BTreeSet, net::Ipv4Addr};

use anyhow::Result;
use k8s_openapi::{
    api::core::v1::{Namespace, Service, ServicePort, ServiceSpec},
    apimachinery::pkg::util::intstr::IntOrString,
};

use crate::api::{CLASS, ENABLED_LABEL, Protocol, ProxyProtocol, PublishedPort, ServiceRequest};

use super::{
    ValidationError,
    primitives::{destination_ipv4, dns_label, dns_subdomain},
};

#[cfg(test)]
mod tests;

const MACHINES: &str = "tunnellb.io/machines";
const POOL: &str = "tunnellb.io/pool";
const REPLICAS: &str = "tunnellb.io/replicas";
const PROXY_PROTOCOL: &str = "tunnellb.io/proxy-protocol";

fn service_error(message: impl Into<String>) -> anyhow::Error {
    ValidationError::InvalidService(message.into()).into()
}

/// Validate namespace authorization and turn Service annotations into an
/// unambiguous request. Unknown annotations are left to their owning controllers.
pub fn service_request(service: &Service, namespace: &Namespace) -> Result<ServiceRequest> {
    let request = request_from_service(service)?;

    if namespace.metadata.name.as_deref() != Some(request.namespace.as_str()) {
        return Err(service_error(
            "Namespace object does not match the Service namespace",
        ));
    }

    if namespace
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(ENABLED_LABEL))
        .map(String::as_str)
        != Some("true")
    {
        return Err(service_error(format!(
            "namespace {} requires label {ENABLED_LABEL}=true",
            request.namespace
        )));
    }

    Ok(request)
}

pub(super) fn request_from_service(service: &Service) -> Result<ServiceRequest> {
    let name = service
        .metadata
        .name
        .as_deref()
        .filter(|s| dns_label(s))
        .ok_or_else(|| service_error("metadata.name must be a DNS label"))?;
    let namespace = service
        .metadata
        .namespace
        .as_deref()
        .filter(|s| dns_label(s))
        .ok_or_else(|| service_error("metadata.namespace must be a DNS label"))?;
    let uid = service
        .metadata
        .uid
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| service_error("metadata.uid is required for allocation ownership"))?;

    let spec = service
        .spec
        .as_ref()
        .ok_or_else(|| service_error("spec is required"))?;
    let cluster_ip = validate_exposure(spec)?;
    let selector = spec
        .selector
        .as_ref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| service_error("a nonempty Pod selector is required"))?;

    if selector
        .iter()
        .any(|(k, v)| !label_key(k) || !label_component(v, true))
    {
        return Err(service_error(
            "selector contains an invalid label key or value",
        ));
    }

    let service_ports = spec
        .ports
        .as_ref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| service_error("at least one Service port is required"))?;
    let mut ports = published_ports(service_ports)?;

    let annotations = service.metadata.annotations.as_ref();
    let annotation = |key: &str| annotations.and_then(|a| a.get(key));
    let mut machines = Vec::new();

    if let Some(value) = annotation(MACHINES) {
        let mut seen = BTreeSet::new();

        for item in value.split(',').map(str::trim) {
            if !dns_subdomain(item) || !seen.insert(item) {
                return Err(service_error(format!(
                    "{MACHINES} must contain unique, nonempty Machine names"
                )));
            }

            machines.push(item.to_owned());
        }
    }

    let pool = annotation(POOL)
        .map(|p| {
            if dns_label(p) {
                Ok(p.clone())
            } else {
                Err(service_error(format!(
                    "{POOL} must be a nonempty DNS label"
                )))
            }
        })
        .transpose()?;

    if !machines.is_empty() && pool.is_some() {
        return Err(service_error(format!(
            "{MACHINES} and {POOL} cannot be combined"
        )));
    }

    let explicit_replicas = annotation(REPLICAS)
        .map(|value| {
            value
                .parse::<u16>()
                .ok()
                .filter(|v| *v > 0 && v.to_string() == *value)
                .ok_or_else(|| {
                    service_error(format!(
                        "{REPLICAS} must be an integer in 1..=65535 without signs or padding"
                    ))
                })
        })
        .transpose()?;
    let replicas = if machines.is_empty() {
        explicit_replicas.unwrap_or(1)
    } else {
        let count = u16::try_from(machines.len())
            .map_err(|_| service_error("too many explicit Machines"))?;

        if explicit_replicas.is_some_and(|replicas| replicas != count) {
            return Err(service_error(format!(
                "{REPLICAS} must equal the explicit Machine count ({count})"
            )));
        }

        count
    };

    if let Some(value) = annotation(PROXY_PROTOCOL) {
        configure_proxy_protocol(&mut ports, value)?;
    }

    Ok(ServiceRequest {
        namespace: namespace.into(),
        name: name.into(),
        uid: uid.into(),
        cluster_ip,
        selector: selector.clone(),
        ports,
        machines,
        pool,
        replicas,
    })
}

fn validate_exposure(spec: &ServiceSpec) -> Result<Ipv4Addr> {
    if spec.type_.as_deref() != Some("LoadBalancer")
        || spec.load_balancer_class.as_deref() != Some(CLASS)
    {
        return Err(service_error(format!(
            "requires type LoadBalancer and explicit loadBalancerClass {CLASS}"
        )));
    }

    if spec.allocate_load_balancer_node_ports != Some(false) {
        return Err(service_error(
            "allocateLoadBalancerNodePorts must be explicitly false",
        ));
    }

    if spec.health_check_node_port.is_some_and(|p| p != 0) {
        return Err(service_error("healthCheckNodePort is not permitted"));
    }

    if spec.external_name.is_some() || spec.external_ips.as_ref().is_some_and(|v| !v.is_empty()) {
        return Err(service_error(
            "externalName and externalIPs are not permitted",
        ));
    }

    if spec.publish_not_ready_addresses == Some(true) {
        return Err(service_error(
            "publishNotReadyAddresses=true is not supported",
        ));
    }

    if spec
        .internal_traffic_policy
        .as_deref()
        .is_some_and(|p| p != "Cluster")
        || spec
            .external_traffic_policy
            .as_deref()
            .is_some_and(|p| p != "Cluster")
    {
        return Err(service_error(
            "internalTrafficPolicy and externalTrafficPolicy must be Cluster",
        ));
    }

    if spec
        .load_balancer_source_ranges
        .as_ref()
        .is_some_and(|ranges| !ranges.is_empty())
        || spec
            .load_balancer_ip
            .as_ref()
            .is_some_and(|ip| !ip.is_empty())
    {
        return Err(service_error(
            "loadBalancerSourceRanges and loadBalancerIP are not supported",
        ));
    }

    let cluster_ip: Ipv4Addr = spec
        .cluster_ip
        .as_deref()
        .and_then(|s| s.parse().ok())
        .filter(|ip| destination_ipv4(*ip))
        .ok_or_else(|| {
            service_error(
                "requires an ordinary IPv4 ClusterIP; headless Services are not permitted",
            )
        })?;

    if spec
        .cluster_ips
        .as_ref()
        .is_some_and(|ips| ips.len() != 1 || ips[0] != cluster_ip.to_string())
        || spec
            .ip_families
            .as_ref()
            .is_some_and(|f| f.as_slice() != ["IPv4"])
        || spec
            .ip_family_policy
            .as_deref()
            .is_some_and(|p| !matches!(p, "SingleStack" | "PreferDualStack"))
    {
        return Err(service_error(
            "requires exactly one IPv4 ClusterIP; dual-stack and unknown IP family policies are not supported",
        ));
    }

    Ok(cluster_ip)
}

fn published_ports(service_ports: &[ServicePort]) -> Result<Vec<PublishedPort>> {
    let mut names = BTreeSet::new();
    let mut bindings = BTreeSet::new();
    let mut ports = Vec::with_capacity(service_ports.len());

    for p in service_ports {
        if p.node_port.is_some_and(|port| port != 0) {
            return Err(service_error("existing nodePorts must be removed"));
        }

        let name = p.name.as_deref().unwrap_or("");

        if (!name.is_empty() && !dns_label(name)) || (name.is_empty() && service_ports.len() > 1) {
            return Err(service_error(
                "each port of a multi-port Service requires a DNS label name",
            ));
        }

        if !names.insert(name) {
            return Err(service_error(format!(
                "duplicate Service port name {name:?}"
            )));
        }

        let protocol = protocol(p.protocol.as_deref())?;
        let port = port_number(p.port, "Service port")?;

        if !bindings.insert((protocol, port)) {
            return Err(service_error(format!(
                "duplicate {} public port {port}",
                protocol.as_str()
            )));
        }

        match &p.target_port {
            Some(IntOrString::Int(value)) => {
                port_number(*value, "targetPort")?;
            }

            Some(IntOrString::String(value)) if !target_port_name(value) => {
                return Err(service_error(format!(
                    "targetPort {value:?} must be a valid named container port"
                )));
            }

            _ => {}
        }

        ports.push(PublishedPort {
            name: name.into(),
            port,
            protocol,
            proxy_protocol: ProxyProtocol::None,
        });
    }

    Ok(ports)
}

fn configure_proxy_protocol(ports: &mut [PublishedPort], value: &str) -> Result<()> {
    let mut seen = BTreeSet::new();

    for entry in value.split(',').map(str::trim) {
        let (name, mode) = entry.split_once('=').ok_or_else(|| {
            service_error(format!(
                "{PROXY_PROTOCOL} entries must be portname=v1|v2|none"
            ))
        })?;

        if name.is_empty() || !seen.insert(name) {
            return Err(service_error(format!(
                "{PROXY_PROTOCOL} contains an empty or duplicate port name"
            )));
        }

        let port = ports.iter_mut().find(|p| p.name == name).ok_or_else(|| {
            service_error(format!("{PROXY_PROTOCOL} references unknown port {name:?}"))
        })?;
        port.proxy_protocol = match mode {
            "none" => ProxyProtocol::None,
            "v1" if port.protocol != Protocol::Udp => ProxyProtocol::V1,
            "v1" => return Err(service_error("PROXY protocol v1 cannot be used with UDP")),
            "v2" => ProxyProtocol::V2,
            _ => {
                return Err(service_error(format!(
                    "unknown PROXY protocol value {mode:?}; expected v1, v2 or none"
                )));
            }
        };
    }

    Ok(())
}

fn label_component(value: &str, allow_empty: bool) -> bool {
    if value.is_empty() {
        return allow_empty;
    }

    value.len() <= 63
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

fn label_key(value: &str) -> bool {
    match value.split_once('/') {
        Some((prefix, name)) => dns_subdomain(prefix) && label_component(name, false),
        None => label_component(value, false),
    }
}

fn target_port_name(value: &str) -> bool {
    value.len() <= 15
        && dns_label(value)
        && value.bytes().any(|c| c.is_ascii_lowercase())
        && !value.contains("--")
}

pub(super) fn port_number(port: i32, field: &str) -> Result<u16> {
    u16::try_from(port)
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| service_error(format!("{field} must be in 1..=65535")))
}

pub(super) fn protocol(value: Option<&str>) -> Result<Protocol> {
    match value.unwrap_or("TCP") {
        "TCP" => Ok(Protocol::Tcp),
        "UDP" => Ok(Protocol::Udp),
        other => Err(service_error(format!(
            "unsupported protocol {other:?}; expected TCP or UDP"
        ))),
    }
}
