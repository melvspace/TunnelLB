//! Pinned, bounded OpenSSH provisioning of shared external FRP hosts.
use std::{net::Ipv4Addr, path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::timeout;

use crate::api::{PortRange, Publication};

mod binary;
mod command;
mod pin;
mod request;
mod scripts;
mod ssh;
#[cfg(test)]
mod test_support;

use binary::{BINARY_LIMIT, binary_digest, parse_architecture};
use command::{execute, isolated_command, private_file, read_limited_file};
use pin::{parse_pin, select_scan_pin};
use request::{FIELD_LIMIT, validate_request};
use scripts::{
    apply_script, enroll_script, probe_script, remove_script, reserve_script, uninstall_script,
};
use ssh::Ssh;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Operation {
    Enroll,
    Reserve,
    Apply,
    Remove,
    Uninstall,
}

// This contains credentials. Deliberately do not derive Debug.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    pub operation: Operation,
    pub address: Ipv4Addr,
    pub ssh_user: String,
    pub ssh_port: u16,
    pub machine_uid: String,
    pub publication: Option<Publication>,
    pub server_config: Option<String>,
    pub server_certificate: Option<String>,
    pub server_private_key: Option<String>,
    pub expected_known_hosts: Option<String>,
    /// Required for Reserve, Apply and Remove: lowercase SHA-256 hex of the exact
    /// persisted server certificate PEM bytes. Enroll/Uninstall use None.
    #[serde(default)]
    pub generation: Option<String>,
    #[serde(default)]
    pub reservation: Option<ReservationRequest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReservationRequest {
    pub control_port_range: PortRange,
    pub excluded_ports: Vec<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AllocationOutcome {
    Reserved { control_port: u16 },
    PortConflict { port: u16 },
    ControlRangeExhausted,
    ReservationChanged,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Outcome {
    pub known_hosts: String,
    pub fingerprint: String,
    /// Empty only for unpinned Enroll discovery. Persist the pin and run pinned
    /// Enroll before considering the host ready; pinned operations return amd64
    /// or arm64.
    pub architecture: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation: Option<AllocationOutcome>,
}

pub(crate) const OPERATION_TIMEOUT: Duration = Duration::from_secs(480);

/// Provision a shared host. No local shell or SSH agent is used. The bundled
/// directory contains `<amd64|arm64>/frps`; no runtime download is performed.
///
/// Unpinned enrollment only discovers a key and returns an empty architecture,
/// without logging in or changing the host. Persist that pin, then run pinned
/// enrollment to install FRP. Supply the pin to all subsequent requests.
/// The caller must report pending remote cleanup if this returns an error.
pub async fn run(request: &Request, key_path: &Path, frp_directory: &Path) -> Result<Outcome> {
    validate_request(request)?;

    timeout(OPERATION_TIMEOUT, run_inner(request, key_path, frp_directory))
        .await
        .context("SSH worker exceeded its 480-second operation deadline; remote cleanup may still be pending")?
}

async fn run_inner(request: &Request, key_path: &Path, frp_directory: &Path) -> Result<Outcome> {
    // /tmp is a private emptyDir in the Job. The extra private directory also
    // prevents interactions with other invocations during local verification.
    tokio::fs::create_dir_all("/tmp/codex").await?;
    let workspace = tempfile::Builder::new()
        .prefix("tunnellb-ssh-")
        .tempdir_in("/tmp/codex")?;
    let pin = if let Some(expected) = &request.expected_known_hosts {
        parse_pin(expected, request.address, request.ssh_port)?
    } else {
        let mut command = isolated_command("ssh-keyscan", workspace.path());
        command.args([
            "-4",
            "-T",
            "5",
            "-p",
            &request.ssh_port.to_string(),
            "-t",
            "ed25519,ecdsa,rsa",
            &request.address.to_string(),
        ]);
        let output = execute(command, &[], Duration::from_secs(25)).await?;
        ensure!(
            output.success,
            "SSH key scan failed; check the address, SSH port and network reachability"
        );
        let pin = select_scan_pin(&output.stdout, request.address, request.ssh_port)?;

        // Discovery is deliberately separate from the first authenticated
        // connection. A failed installation cannot discard the trusted key and
        // silently rescan a replacement on a subsequent attempt.
        return Ok(Outcome {
            known_hosts: pin.line,
            fingerprint: pin.fingerprint,
            architecture: String::new(),
            allocation: None,
        });
    };

    let key = read_limited_file(key_path, FIELD_LIMIT as u64)
        .await
        .context("reading mounted SSH private key")?;
    ensure!(!key.is_empty(), "SSH private key is empty");
    let private_key = workspace.path().join("identity");
    private_file(&private_key, &key).await?;
    let known_hosts = workspace.path().join("known_hosts");
    private_file(&known_hosts, pin.line.as_bytes()).await?;
    let ssh = Ssh {
        request,
        home: workspace.path(),
        key: &private_key,
        known_hosts: &known_hosts,
        host_algorithm: &pin.algorithm,
    };

    let probe = ssh
        .script(&probe_script(request), Duration::from_secs(45))
        .await?;
    let architecture = parse_architecture(&probe)?;
    let expected_digest = binary_digest(&architecture)?;
    let script = match request.operation {
        Operation::Enroll => {
            // Do not retransmit ~20 MiB on every reconciliation. The digest is
            // probed over the pinned session and checked again under the lock.
            let installed = probe
                .lines()
                .any(|line| line == format!("TUNNELLB_BINARY {expected_digest}"));
            let binary = if installed {
                None
            } else {
                let path = frp_directory.join(&architecture).join("frps");
                let bytes = read_limited_file(&path, BINARY_LIMIT)
                    .await
                    .context("reading bundled FRP binary for the detected architecture")?;
                ensure!(
                    hex::encode(Sha256::digest(&bytes)) == expected_digest,
                    "bundled frps checksum mismatch; rebuild the image with the pinned official FRP 0.71.1 binary"
                );

                Some(bytes)
            };

            enroll_script(request, binary.as_deref(), expected_digest)?
        }

        Operation::Reserve => reserve_script(request)?,
        Operation::Apply => apply_script(request)?,
        Operation::Remove => remove_script(request)?,
        Operation::Uninstall => uninstall_script(request)?,
    };

    let output = ssh.script(&script, Duration::from_secs(390)).await?;
    let allocation = if request.operation == Operation::Reserve {
        Some(scripts::parse_allocation(&output)?)
    } else {
        None
    };

    Ok(Outcome {
        known_hosts: pin.line,
        fingerprint: pin.fingerprint,
        architecture,
        allocation,
    })
}
