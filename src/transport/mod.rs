//! Credentials and immutable FRP configuration for one Service/Server publication.
//!
//! Field names and behavior are pinned to fatedier/frp v0.71.1:
//! `conf/{frpc,frps}_full_example.toml`, `pkg/transport/tls.go`, and
//! `pkg/proto/udp/udp.go`. Persist credentials once per publication; generating
//! them again rotates both the authentication token and the pinned certificate.

use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use rand::{TryRngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::api::{Protocol, ProxyProtocol, Publication};

pub const FRP_VERSION: &str = "0.71.1";

/// Identify the persisted credential generation without disclosing its secrets.
/// Hash the exact PEM bytes stored in the publication Secret, without trimming
/// or re-encoding. A removed generation must never be reused.
pub fn credential_generation(certificate_pem: &str) -> String {
    hex::encode(Sha256::digest(certificate_pem.as_bytes()))
}

/// Secret material. Deliberately does not implement `Debug`.
///
/// Only the certificate and generated frpc configuration belong in the
/// connector Secret. The TLS private key belongs on the remote server.
#[derive(Serialize, Deserialize)]
pub struct Credentials {
    pub token: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
}

/// Generate an independent 256-bit token and self-signed server certificate.
///
/// The certificate's IP SAN matches the Server address. Clients trust only this
/// certificate, not the system CA store. rcgen's long-lived validity defaults
/// allow persisted publications to keep running during controller outages;
/// rotation/revocation is the caller's responsibility.
pub fn credentials(publication: &Publication) -> Result<Credentials> {
    validate_publication(publication)?;

    let mut token = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut token)
        .context("generating publication authentication token")?;
    let certificate =
        rcgen::generate_simple_self_signed(vec![publication.server_address.to_string()])
            .context("generating publication TLS certificate")?;

    Ok(Credentials {
        token: hex::encode(token),
        certificate_pem: certificate.cert.pem(),
        private_key_pem: certificate.signing_key.serialize_pem(),
    })
}

/// Generate the secret configuration of this publication's dedicated frps.
///
/// The caller must install the matching PEM files at the emitted paths and keep
/// this configuration private: FRP token authentication needs the shared token
/// on both ends. `allowPorts` restricts numeric ports, not protocol/port pairs;
/// FRP 0.71.1 cannot express a protocol-specific server allowlist.
pub fn server_config(publication: &Publication, credentials: &Credentials) -> Result<String> {
    validate_publication(publication)?;
    validate_token(credentials)?;

    let directory = format!(
        "/var/lib/tunnellb/{}/publications/{}",
        publication.server_uid, publication.id
    );
    let ports: BTreeSet<_> = publication
        .service
        .ports
        .iter()
        .map(|port| port.port)
        .collect();
    let allow_ports: Vec<_> = ports
        .into_iter()
        .map(|port| json!({ "single": port }))
        .collect();

    toml::to_string_pretty(&json!({
        "bindAddr": "0.0.0.0",
        "bindPort": publication.control_port,
        "proxyBindAddr": "0.0.0.0",
        "allowPorts": allow_ports,
        "maxPortsPerClient": publication.service.ports.len(),
        "auth": auth(credentials),
        "transport": {
            "tls": {
                "force": true,
                "certFile": format!("{directory}/tls.crt"),
                "keyFile": format!("{directory}/tls.key"),
            },
        },
        "log": logging(),
    }))
    .context("serializing publication server configuration")
}

/// Generate frpc configuration to store in a Secret, never command-line flags.
///
/// Proxy names are `<publication-id>-<tcp|udp>-<port>` with no user prefix.
/// Both local and remote ports are the Service port; Kubernetes handles target
/// ports behind the ClusterIP. No plugin, visitor, admin API, or include can
/// change the explicitly configured destinations.
pub fn client_config(publication: &Publication, credentials: &Credentials) -> Result<String> {
    validate_publication(publication)?;
    validate_token(credentials)?;

    let mut ports: Vec<_> = publication.service.ports.iter().collect();
    ports.sort_by_key(|port| (port.protocol, port.port));
    let proxies: Vec<_> = ports
        .into_iter()
        .map(|port| {
            let mut proxy = json!({
                "name": format!("{}-{}-{}", publication.id, port.protocol.frp_name(), port.port),
                "type": port.protocol.frp_name(),
                "localIP": publication.service.cluster_ip.to_string(),
                "localPort": port.port,
                "remotePort": port.port,
            });
            let version = match port.proxy_protocol {
                ProxyProtocol::None => None,
                ProxyProtocol::V1 => Some("v1"),
                ProxyProtocol::V2 => Some("v2"),
            };

            if let Some(version) = version {
                proxy["transport"] = json!({ "proxyProtocolVersion": version });
            }

            proxy
        })
        .collect();

    toml::to_string_pretty(&json!({
        "serverAddr": publication.server_address.to_string(),
        "serverPort": publication.control_port,
        "loginFailExit": false,
        "auth": auth(credentials),
        "transport": {
            "protocol": "tcp",
            "tls": {
                "enable": true,
                "trustedCaFile": "/etc/tunnellb/ca.crt",
                "serverName": publication.server_address.to_string(),
            },
        },
        "log": logging(),
        "proxies": proxies,
    }))
    .context("serializing publication client configuration")
}

fn auth(credentials: &Credentials) -> Value {
    json!({
        "method": "token",
        "token": credentials.token,
        "additionalScopes": ["HeartBeats", "NewWorkConns"],
    })
}

fn logging() -> Value {
    // The connector readiness parser observes control-connection exits at debug.
    json!({ "to": "console", "level": "debug", "disablePrintColor": true })
}

fn validate_token(credentials: &Credentials) -> Result<()> {
    // FRP renders Go templates BEFORE parsing TOML. Quoting alone cannot safely
    // encode arbitrary credentials containing template directives such as {{...}}.
    ensure!(
        credentials.token.len() == 64
            && credentials
                .token
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "publication token must be 32 bytes encoded as hexadecimal"
    );

    Ok(())
}

fn validate_publication(publication: &Publication) -> Result<()> {
    validate_path_component(&publication.id, "publication ID")?;
    validate_path_component(&publication.server_uid, "Server UID")?;
    ensure!(
        publication.control_port != 0,
        "publication control port must be nonzero"
    );
    ensure!(
        !publication.service.ports.is_empty(),
        "publication must have at least one public port"
    );

    let mut ports = BTreeSet::new();

    for port in &publication.service.ports {
        ensure!(port.port != 0, "public ports must be nonzero");
        ensure!(
            port.protocol != Protocol::Tcp || port.port != publication.control_port,
            "public TCP ports must not overlap the reserved TCP control port"
        );
        ensure!(
            ports.insert((port.protocol, port.port)),
            "duplicate public protocol/port pair"
        );
        // PROXY v1 has no UDP address format. FRP's UDP forwarder supports v2,
        // but emits its header only on the first datagram of a tracked flow.
        ensure!(
            port.protocol != Protocol::Udp || port.proxy_protocol != ProxyProtocol::V1,
            "UDP requires PROXY protocol v2 or no PROXY protocol"
        );
    }

    Ok(())
}

fn validate_path_component(value: &str, field: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 63
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "{field} must contain 1-63 ASCII letters, digits, hyphens or underscores"
    );

    Ok(())
}

#[cfg(test)]
mod tests;
