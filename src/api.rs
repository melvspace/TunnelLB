use std::{collections::BTreeMap, net::Ipv4Addr};

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const GROUP: &str = "tunnellb.io";
pub const CLASS: &str = "tunnellb.io/edge";
pub const FINALIZER: &str = "tunnellb.io/cleanup";
pub const ENABLED_LABEL: &str = "tunnellb.io/enabled";
pub const MANAGED_LABEL: &str = "app.kubernetes.io/managed-by";
pub const SERVER_LABEL: &str = "tunnellb.io/server";
pub const SERVICE_UID_LABEL: &str = "tunnellb.io/service-uid";
pub const PUBLICATION_LABEL: &str = "tunnellb.io/publication";

#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(group = "tunnellb.io", version = "v1alpha1", kind = "Server")]
#[kube(status = "ServerStatus", shortname = "tlbs")]
#[kube(printcolumn = r#"{"name":"Address","type":"string","jsonPath":".spec.address"}"#)]
#[kube(printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#)]
#[serde(rename_all = "camelCase")]
pub struct ServerSpec {
    /// Existing IPv4 address of the external server.
    pub address: String,
    pub ssh: SshSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<String>,
    /// Empty means all administrator-enabled namespaces.
    #[serde(default)]
    pub allowed_namespaces: Vec<String>,
    #[serde(default)]
    pub reserved_ports: Vec<u16>,
    #[serde(default)]
    pub control_port_range: PortRange,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshSpec {
    pub user: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub private_key_secret_ref: SecretReference,
}

fn default_ssh_port() -> u16 {
    22
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretReference {
    pub name: String,
    #[serde(default = "default_key")]
    pub key: String,
}

fn default_key() -> String {
    "ssh-privatekey".into()
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl Default for PortRange {
    fn default() -> Self {
        Self {
            start: 20000,
            end: 29999,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServerStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolled_revision: Option<String>,
    #[serde(default)]
    pub observed_generation: i64,
    pub phase: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }

    pub fn frp_name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
    #[default]
    None,
    V1,
    V2,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishedPort {
    pub name: String,
    pub port: u16,
    pub protocol: Protocol,
    pub proxy_protocol: ProxyProtocol,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceRequest {
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub cluster_ip: Ipv4Addr,
    pub selector: BTreeMap<String, String>,
    pub ports: Vec<PublishedPort>,
    pub servers: Vec<String>,
    pub pool: Option<String>,
    pub replicas: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendPort {
    pub protocol: Protocol,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatedService {
    pub request: ServiceRequest,
    pub backend_ports: Vec<BackendPort>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Publication {
    pub id: String,
    pub server_name: String,
    pub server_uid: String,
    pub server_address: Ipv4Addr,
    pub control_port: u16,
    pub service: ServiceRequest,
}
