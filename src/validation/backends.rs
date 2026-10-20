use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use anyhow::Result;
use k8s_openapi::{
    api::{
        core::v1::{Pod, Service, ServicePort},
        discovery::v1::{Endpoint, EndpointSlice},
    },
    apimachinery::pkg::util::intstr::IntOrString,
};

use crate::api::{BackendPort, Protocol, ServiceRequest};

use super::{
    ValidationError,
    primitives::{destination_ipv4, parse_ipv4_or_mapped},
    service::{port_number, protocol, request_from_service},
};

#[cfg(test)]
mod tests;

const SLICE_MANAGER: &str = "endpointslice.kubernetes.io/managed-by";
const SLICE_SERVICE: &str = "kubernetes.io/service-name";

fn backend_error(message: impl Into<String>) -> anyhow::Error {
    ValidationError::UnsafeBackend(message.into()).into()
}

/// Supply all slices associated with this Service, including manual ones.
/// Every slice and endpoint must have valid provenance and structure. Endpoints
/// that kube-proxy may route must also resolve to a verified Pod, even when
/// another backend is ready. Explicitly nonroutable endpoints may outlive Pods.
pub fn validate_backends(
    request: &ServiceRequest,
    service: &Service,
    slices: &[EndpointSlice],
    pods: &[Pod],
) -> Result<Vec<BackendPort>> {
    let current = request_from_service(service)?;

    if &current != request {
        return Err(backend_error(
            "ServiceRequest does not match the current Service",
        ));
    }

    // The request parser guarantees a nonempty spec.ports.
    let service_ports = service
        .spec
        .as_ref()
        .and_then(|s| s.ports.as_ref())
        .unwrap();
    let mut pod_index = BTreeMap::new();

    for pod in pods {
        if pod.metadata.namespace.as_deref() != Some(request.namespace.as_str()) {
            continue;
        }

        if let Some(name) = pod.metadata.name.as_deref()
            && pod_index.insert(name, pod).is_some()
        {
            return Err(backend_error(format!(
                "duplicate Pod object {}/{name}",
                request.namespace
            )));
        }
    }

    let mut ready_ports = BTreeSet::new();
    let mut backend_ports = BTreeSet::new();
    let mut unavailable = BTreeMap::<String, usize>::new();

    for slice in slices {
        let slice_ports = validate_slice(request, service_ports, slice)?;
        let invalid = |reason: &str| slice_error(slice, reason);

        for endpoint in &slice.endpoints {
            let Some(pod) = validate_endpoint(request, endpoint, &pod_index)
                .map_err(|e| invalid(&e.to_string()))?
            else {
                *unavailable
                    .entry("endpoint is not ready".into())
                    .or_default() += 1;
                continue;
            };

            for (&index, &number) in &slice_ports {
                let expected =
                    resolve_target(&service_ports[index], request.ports[index].protocol, pod)
                        .map_err(|e| invalid(&e.to_string()))?;

                if number != expected {
                    return Err(invalid(&format!(
                        "Pod {} port {:?} resolves to {expected}, but slice advertises {number}",
                        pod.metadata.name.as_deref().unwrap_or("<unnamed>"),
                        request.ports[index].name
                    )));
                }
            }

            let reason = if slice_ports.is_empty() {
                Some("endpoint has no resolved Service ports")
            } else if slice.metadata.deletion_timestamp.is_some() {
                Some("EndpointSlice is deleting")
            } else {
                unavailable_reason(endpoint, pod)
            };

            if let Some(reason) = reason {
                *unavailable.entry(reason.into()).or_default() += 1;
                continue;
            }

            for (&index, &number) in &slice_ports {
                ready_ports.insert(index);
                backend_ports.insert((request.ports[index].protocol, number));
            }
        }
    }

    if ready_ports.len() != request.ports.len() {
        let missing = request
            .ports
            .iter()
            .enumerate()
            .filter(|(i, _)| !ready_ports.contains(i))
            .map(|(_, p)| {
                format!(
                    "{}:{}/{}",
                    if p.name.is_empty() {
                        "<unnamed>"
                    } else {
                        &p.name
                    },
                    p.port,
                    p.protocol.as_str()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let reasons = if unavailable.is_empty() {
            "no endpoints advertise these Service ports".to_owned()
        } else {
            unavailable
                .into_iter()
                .map(|(reason, count)| format!("{reason} ({count})"))
                .collect::<Vec<_>>()
                .join("; ")
        };

        return Err(ValidationError::BackendUnavailable(format!(
            "no eligible ready backend for {missing}: {reasons}"
        ))
        .into());
    }

    Ok(backend_ports
        .into_iter()
        .map(|(protocol, port)| BackendPort { protocol, port })
        .collect())
}

fn slice_error(slice: &EndpointSlice, reason: &str) -> anyhow::Error {
    let slice_name = slice.metadata.name.as_deref().unwrap_or("<unnamed>");
    backend_error(format!("EndpointSlice {slice_name}: {reason}"))
}

fn validate_slice(
    request: &ServiceRequest,
    service_ports: &[ServicePort],
    slice: &EndpointSlice,
) -> Result<BTreeMap<usize, u16>> {
    let invalid = |reason: &str| slice_error(slice, reason);

    if slice.metadata.namespace.as_deref() != Some(request.namespace.as_str()) {
        return Err(invalid("namespace does not match the Service"));
    }

    let labels = slice.metadata.labels.as_ref();

    if labels
        .and_then(|l| l.get(SLICE_SERVICE))
        .map(String::as_str)
        != Some(request.name.as_str())
    {
        return Err(invalid(
            "kubernetes.io/service-name does not match the Service",
        ));
    }

    if labels
        .and_then(|l| l.get(SLICE_MANAGER))
        .map(String::as_str)
        != Some("endpointslice-controller.k8s.io")
    {
        return Err(invalid(
            "must be managed by endpointslice-controller.k8s.io; manual/external endpoints are forbidden",
        ));
    }

    let owners = slice
        .metadata
        .owner_references
        .as_deref()
        .unwrap_or_default();

    if owners.len() != 1
        || owners[0].api_version != "v1"
        || owners[0].kind != "Service"
        || owners[0].name != request.name
        || owners[0].uid != request.uid
        || owners[0].controller != Some(true)
    {
        return Err(invalid(
            "controller owner must be this Service with its exact UID",
        ));
    }

    if slice.address_type != "IPv4" {
        return Err(invalid("addressType must be IPv4"));
    }

    let mut slice_ports = BTreeMap::new();

    for port in slice.ports.iter().flatten() {
        let name = port.name.as_deref().unwrap_or("");
        let proto = protocol(port.protocol.as_deref()).map_err(|e| invalid(&e.to_string()))?;
        let index = request
            .ports
            .iter()
            .position(|p| p.name == name && p.protocol == proto)
            .ok_or_else(|| invalid(&format!("unknown Service port {name:?}/{}", proto.as_str())))?;
        let number = port
            .port
            .ok_or_else(|| invalid("port must be explicit; wildcard ports are forbidden"))?;
        let number =
            port_number(number, "EndpointSlice port").map_err(|e| invalid(&e.to_string()))?;

        if slice_ports.insert(index, number).is_some() {
            return Err(invalid(&format!(
                "duplicate port {name:?}/{}",
                proto.as_str()
            )));
        }

        if let Some(expected) = numeric_target(&service_ports[index])
            && number != expected
        {
            return Err(invalid(&format!(
                "port {name:?} is {number}, expected Service targetPort {expected}"
            )));
        }
    }

    Ok(slice_ports)
}

fn validate_endpoint<'a>(
    request: &ServiceRequest,
    endpoint: &Endpoint,
    pods: &BTreeMap<&str, &'a Pod>,
) -> Result<Option<&'a Pod>> {
    let reference = endpoint
        .target_ref
        .as_ref()
        .ok_or_else(|| backend_error("endpoint targetRef must identify a Pod"))?;

    // The built-in EndpointSlice controller omits apiVersion on Pod references.
    if reference
        .api_version
        .as_deref()
        .is_some_and(|v| !matches!(v, "" | "v1"))
        || reference.kind.as_deref() != Some("Pod")
        || reference.namespace.as_deref() != Some(request.namespace.as_str())
        || reference
            .field_path
            .as_deref()
            .is_some_and(|p| !p.is_empty())
    {
        return Err(backend_error(
            "targetRef must reference a whole v1 Pod in the Service namespace",
        ));
    }

    let name = reference
        .name
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| backend_error("targetRef.name is required"))?;
    let uid = reference
        .uid
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| backend_error("targetRef.uid is required"))?;

    if endpoint.addresses.len() != 1 {
        return Err(backend_error(format!(
            "Pod {name} endpoint must contain exactly one IPv4 address"
        )));
    }

    let address = &endpoint.addresses[0];
    let ip: Ipv4Addr = address
        .parse()
        .ok()
        .filter(|ip| destination_ipv4(*ip))
        .ok_or_else(|| {
            backend_error(format!(
                "Pod {name} endpoint address must be an ordinary unicast IPv4 address"
            ))
        })?;

    // Cluster-policy kube-proxy can fall back to serving, terminating endpoints.
    // Missing serving defaults to true, so ready=false alone cannot exempt them.
    if endpoint.conditions.as_ref().is_some_and(|conditions| {
        conditions.ready == Some(false)
            && (conditions.terminating != Some(true) || conditions.serving == Some(false))
    }) {
        return Ok(None);
    }

    let pod = *pods.get(name).ok_or_else(|| {
        backend_error(format!(
            "referenced Pod {name} is absent; cannot verify its identity"
        ))
    })?;

    if pod.metadata.uid.as_deref() != Some(uid) {
        return Err(backend_error(format!(
            "targetRef UID does not match Pod {name}"
        )));
    }

    if request
        .selector
        .iter()
        .any(|(key, value)| pod.metadata.labels.as_ref().and_then(|l| l.get(key)) != Some(value))
    {
        return Err(backend_error(format!(
            "Pod {name} does not match the Service selector"
        )));
    }

    let spec = pod
        .spec
        .as_ref()
        .ok_or_else(|| backend_error(format!("Pod {name} has no spec")))?;

    if spec.host_network == Some(true) {
        return Err(backend_error(format!("Pod {name} uses hostNetwork")));
    }

    let status = pod
        .status
        .as_ref()
        .ok_or_else(|| backend_error(format!("Pod {name} has no status IP")))?;

    if status.pod_ip.as_ref() != Some(address)
        && !status.pod_ips.iter().flatten().any(|p| p.ip == *address)
    {
        return Err(backend_error(format!(
            "endpoint {address} does not equal a status IP of Pod {name}"
        )));
    }

    if status.host_ip.as_deref().and_then(parse_ipv4_or_mapped) == Some(ip)
        || status
            .host_ips
            .iter()
            .flatten()
            .any(|p| parse_ipv4_or_mapped(&p.ip) == Some(ip))
    {
        return Err(backend_error(format!(
            "endpoint {address} equals the host IP of Pod {name}"
        )));
    }

    Ok(Some(pod))
}

fn numeric_target(port: &ServicePort) -> Option<u16> {
    match &port.target_port {
        None => u16::try_from(port.port).ok(),
        Some(IntOrString::Int(value)) => u16::try_from(*value).ok(),
        Some(IntOrString::String(_)) => None,
    }
}

fn resolve_target(port: &ServicePort, protocol: Protocol, pod: &Pod) -> Result<u16> {
    if let Some(number) = numeric_target(port) {
        return Ok(number);
    }

    let Some(IntOrString::String(name)) = &port.target_port else {
        return Err(backend_error("invalid targetPort"));
    };

    let spec = pod
        .spec
        .as_ref()
        .ok_or_else(|| backend_error("Pod spec is missing"))?;

    // Kubernetes also resolves named ports on restartable init containers.
    let containers = spec.containers.iter().chain(
        spec.init_containers
            .iter()
            .flatten()
            .filter(|c| c.restart_policy.as_deref() == Some("Always")),
    );
    let mut matches = containers
        .flat_map(|c| c.ports.iter().flatten())
        .filter(|p| {
            p.name.as_deref() == Some(name)
                && p.protocol.as_deref().unwrap_or("TCP") == protocol.as_str()
        });
    let matched = matches.next().ok_or_else(|| {
        backend_error(format!(
            "Pod {} has no named targetPort {name:?}/{}",
            pod.metadata.name.as_deref().unwrap_or("<unnamed>"),
            protocol.as_str()
        ))
    })?;

    if matches.next().is_some() {
        return Err(backend_error(format!(
            "Pod has ambiguous named targetPort {name:?}"
        )));
    }

    port_number(matched.container_port, "containerPort").map_err(|e| backend_error(e.to_string()))
}

fn unavailable_reason(endpoint: &Endpoint, pod: &Pod) -> Option<&'static str> {
    let conditions = endpoint.conditions.as_ref();

    if conditions.and_then(|c| c.terminating) == Some(true)
        || pod.metadata.deletion_timestamp.is_some()
    {
        Some("endpoint or Pod is terminating")
    } else if conditions.and_then(|c| c.ready) == Some(false) {
        Some("endpoint is not ready")
    } else if conditions.and_then(|c| c.serving) == Some(false) {
        Some("endpoint is not serving")
    } else if pod.status.as_ref().and_then(|s| s.phase.as_deref()) != Some("Running") {
        Some("Pod is not Running")
    } else if !pod.status.as_ref().is_some_and(|s| {
        s.conditions
            .iter()
            .flatten()
            .any(|c| c.type_ == "Ready" && c.status == "True")
    }) {
        Some("Pod Ready condition is not True")
    } else {
        None
    }
}
