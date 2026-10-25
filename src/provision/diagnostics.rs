//! Only these fixed diagnostics may cross worker and controller boundaries.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "kebab-case")]
pub enum Diagnostic {
    #[error(
        "Could not inspect UFW state; reconciliation will retry. Check that UFW is functional."
    )]
    FirewallInspection,
    #[error(
        "Could not configure TunnelLB's UFW rules; reconciliation will retry. Check UFW and TunnelLB's owned application profiles."
    )]
    FirewallConfiguration,
    #[error(
        "Could not remove TunnelLB's owned UFW rules; cleanup will retry and port claims remain reserved. Check UFW and TunnelLB's owned application profiles."
    )]
    FirewallCleanup,
    #[error(
        "TunnelLB has recorded UFW rules but UFW is unavailable; restore UFW so automatic reconciliation and cleanup can continue."
    )]
    FirewallUnavailable,
    #[error(
        "The worker could not reach the publication's TCP control port within 5 seconds after Apply. Check the Server address, control port, host/provider firewalls and cluster egress; connector readiness is still required."
    )]
    ControlUnreachable,
    #[serde(rename = "sudo")]
    #[error("SSH account requires root or noninteractive sudo access")]
    RemoteSudo,
    #[serde(rename = "platform")]
    #[error("external host must run Debian or Ubuntu with systemd as PID 1")]
    RemotePlatform,
    #[serde(rename = "platform-version")]
    #[error("FRP hardening requires systemd 244 or newer; upgrade the dedicated host")]
    RemotePlatformVersion,
    #[serde(rename = "architecture")]
    #[error("external host architecture must be amd64 or arm64")]
    RemoteArchitecture,
    #[serde(rename = "prerequisites")]
    #[error(
        "external host is missing required system tools; install iproute2, util-linux and coreutils"
    )]
    RemotePrerequisites,
    #[serde(rename = "dedicated-host")]
    #[error(
        "external host appears to have k3s or Tailscale installed; use a dedicated host outside the cluster and its VPN"
    )]
    RemoteDedicatedHost,
    #[serde(rename = "owner")]
    #[error("host ownership marker is absent or belongs to another Server UID; refusing takeover")]
    RemoteOwner,
    #[serde(rename = "legacy-layout")]
    #[error(
        "legacy single-owner TunnelLB layout detected; uninstall with the old worker and explicitly reset its retained ownership markers before shared-host enrollment"
    )]
    RemoteLegacyLayout,
    #[serde(rename = "server-revoked")]
    #[error(
        "Server UID was uninstalled; explicit administrator ownership reset is required before re-enrollment"
    )]
    RemoteServerRevoked,
    #[serde(rename = "generation-revoked")]
    #[error("publication credential generation was revoked; delayed Apply cannot restore it")]
    RemoteGenerationRevoked,
    #[serde(rename = "generation-conflict")]
    #[error(
        "publication has a different reserved credential generation or configuration; remove it before applying replacement credentials"
    )]
    RemoteGenerationConflict,
    #[serde(rename = "generation-state")]
    #[error(
        "publication generation ownership is missing or malformed; refusing ambiguous cleanup or replacement"
    )]
    RemoteGenerationState,
    #[serde(rename = "claim-state")]
    #[error(
        "host-wide port claim is missing or malformed; restore owned reservation state before retrying"
    )]
    RemoteClaimState,
    #[serde(rename = "reservation-required")]
    #[error("publication must reserve host-wide ports before Apply")]
    RemoteReservationRequired,
    #[serde(rename = "socket-state")]
    #[error("host socket inspection returned malformed numeric listener state")]
    RemoteSocketState,
    #[serde(rename = "reservation-conflict")]
    #[error(
        "publication reservation has different credentials or ports; remove it before reserving a replacement"
    )]
    RemoteReservationConflict,
    #[serde(rename = "account-owner")]
    #[error("FRP system account conflicts with an existing account; refusing to reuse it")]
    RemoteAccountOwner,
    #[serde(rename = "unit-owner")]
    #[error(
        "FRP systemd unit or drop-in is not owned or has changed; restore owned configuration before retrying"
    )]
    RemoteUnitOwner,
    #[serde(rename = "unsafe-path")]
    #[error(
        "owned host path has an unexpected owner, type or symlink; refusing unsafe modification"
    )]
    RemoteUnsafePath,
    #[serde(rename = "busy")]
    #[error("another TunnelLB worker owns the remote provisioning lock; retry later")]
    RemoteBusy,
    #[serde(rename = "checksum")]
    #[error(
        "remote FRP checksum does not match the immutable pinned binary; administrator repair is required"
    )]
    RemoteChecksum,
    #[serde(rename = "configuration")]
    #[error(
        "FRP rejected the staged server configuration; check the publication and stored credentials"
    )]
    RemoteConfiguration,
    #[serde(rename = "occupied-port")]
    #[error(
        "a requested public or control port is occupied outside this publication; select unused ports"
    )]
    RemoteOccupiedPort,
    #[serde(rename = "start")]
    #[error(
        "owned FRP unit failed to start; inspect its systemd journal and verify certificates and port availability"
    )]
    RemoteStart,
    #[serde(rename = "stop")]
    #[error("owned FRP unit could not be stopped; remote cleanup remains pending")]
    RemoteStop,
    #[error(
        "SSH host key does not match the stored pin; investigate the host change and explicitly re-enroll."
    )]
    SshHostKeyMismatch,
    #[error(
        "SSH public-key authentication failed; check sshUser and the mounted private key against the host authorized_keys."
    )]
    SshAuthentication,
    #[error(
        "SSH connection refused; check the Server address, SSH port and whether sshd is listening."
    )]
    SshConnectionRefused,
    #[error("SSH host is unreachable; check routing, cluster egress and host/provider firewalls.")]
    SshUnreachable,
    #[error("SSH command timed out; check network reachability and pending remote cleanup.")]
    SshTimeout,
    #[error(
        "SSH could not load the private key; provide a valid, unencrypted OpenSSH private key."
    )]
    SshKeyInvalid,
    #[error(
        "SSH algorithm negotiation failed; check the host SSH algorithms and stored host-key pin."
    )]
    SshNegotiation,
    #[error(
        "SSH connection was closed or reset by the host; check sshd logs and connection limits."
    )]
    SshConnectionClosed,
    #[error(
        "SSH subprocess failed or exceeded its output limit; check the worker image and resources."
    )]
    SshProcess,
    #[error("Could not start OpenSSH; ensure openssh-client is installed in the worker image.")]
    SshStart,
    #[error(
        "SSH host-key discovery failed; check the Server address, SSH port, network reachability and supported host keys."
    )]
    SshScan,
    #[error(
        "SSH worker request is invalid or exceeds its size limit; check the generated request and Server configuration."
    )]
    InvalidRequest,
    #[error("Could not read the SSH worker request; check the mounted request Secret.")]
    RequestRead,
    #[error("Could not read the SSH private key or it is empty; check the mounted SSH Secret.")]
    PrivateKeyRead,
    #[error("Stored SSH host-key pin is invalid for this address and port; check the Server pin.")]
    HostPinInvalid,
    #[error("Could not prepare the SSH workspace; check worker temporary storage and permissions.")]
    Workspace,
    #[error(
        "Bundled FRP binary is missing, unreadable or has an incorrect checksum; rebuild the worker image with the pinned binary."
    )]
    BundledBinary,
    #[error(
        "Remote provisioning failed without a recognized diagnostic; inspect sshd and systemd logs on the host and verify root or passwordless sudo access. Remote cleanup may remain pending."
    )]
    RemoteFailed,
    #[error(
        "Remote worker returned an invalid result or no success marker; check host prerequisites and the worker image."
    )]
    RemoteOutput,
    #[error(
        "Could not write the SSH worker termination result; check the result path and volume permissions."
    )]
    ResultWrite,
    #[error(
        "SSH worker result could not be encoded within the 4096-byte termination message limit."
    )]
    ResultEncoding,
    #[serde(rename = "SSH worker failed")]
    #[error("SSH worker failed")]
    WorkerFailed,
}

impl Diagnostic {
    pub(crate) fn from_remote_marker(code: &str) -> Option<Self> {
        match code {
            "firewall-inspection" => Some(Self::FirewallInspection),
            "firewall-configuration" => Some(Self::FirewallConfiguration),
            "firewall-cleanup" => Some(Self::FirewallCleanup),
            "firewall-unavailable" => Some(Self::FirewallUnavailable),
            "control-unreachable" => Some(Self::ControlUnreachable),
            "sudo" => Some(Self::RemoteSudo),
            "platform" => Some(Self::RemotePlatform),
            "platform-version" => Some(Self::RemotePlatformVersion),
            "architecture" => Some(Self::RemoteArchitecture),
            "prerequisites" => Some(Self::RemotePrerequisites),
            "dedicated-host" => Some(Self::RemoteDedicatedHost),
            "owner" => Some(Self::RemoteOwner),
            "legacy-layout" => Some(Self::RemoteLegacyLayout),
            "server-revoked" => Some(Self::RemoteServerRevoked),
            "generation-revoked" => Some(Self::RemoteGenerationRevoked),
            "generation-conflict" => Some(Self::RemoteGenerationConflict),
            "generation-state" => Some(Self::RemoteGenerationState),
            "claim-state" => Some(Self::RemoteClaimState),
            "reservation-required" => Some(Self::RemoteReservationRequired),
            "socket-state" => Some(Self::RemoteSocketState),
            "reservation-conflict" => Some(Self::RemoteReservationConflict),
            "account-owner" => Some(Self::RemoteAccountOwner),
            "unit-owner" => Some(Self::RemoteUnitOwner),
            "unsafe-path" => Some(Self::RemoteUnsafePath),
            "busy" => Some(Self::RemoteBusy),
            "checksum" => Some(Self::RemoteChecksum),
            "configuration" => Some(Self::RemoteConfiguration),
            "occupied-port" => Some(Self::RemoteOccupiedPort),
            "start" => Some(Self::RemoteStart),
            "stop" => Some(Self::RemoteStop),
            _ => None,
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::FirewallInspection => "FirewallInspectionFailed",
            Self::FirewallConfiguration => "FirewallConfigurationFailed",
            Self::FirewallCleanup => "FirewallCleanupFailed",
            Self::FirewallUnavailable => "FirewallUnavailable",
            Self::ControlUnreachable => "ControlUnreachable",
            _ => "SSHFailed",
        }
    }
}

/// The termination envelope carries an allowlisted code, never an error string.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureOutcome {
    pub error: Diagnostic,
}

impl FailureOutcome {
    pub fn from_error(error: &anyhow::Error) -> Self {
        Self {
            error: error
                .downcast_ref::<Diagnostic>()
                .copied()
                .unwrap_or(Diagnostic::WorkerFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_context_and_unrecognized_messages_never_cross_the_boundary() {
        let error =
            anyhow::Error::new(Diagnostic::FirewallConfiguration).context("SECRET_SENTINEL");
        let result = FailureOutcome::from_error(&error);
        assert_eq!(
            serde_json::to_string(&result).unwrap(),
            r#"{"error":"firewall-configuration"}"#
        );
        assert!(!result.error.to_string().contains("SECRET_SENTINEL"));
        let forged = anyhow::anyhow!("firewall-configuration SECRET_SENTINEL");
        assert_eq!(
            FailureOutcome::from_error(&forged).error,
            Diagnostic::WorkerFailed
        );
    }

    #[test]
    fn envelopes_reject_unknown_codes_and_extra_fields() {
        for message in [
            r#"{"error":"SECRET_SENTINEL"}"#,
            r#"{"error":"control-unreachable","message":"SECRET_SENTINEL"}"#,
            r#"{"error":{"code":"firewall-cleanup"}}"#,
            r#"{"error":"firewall-cleanup SECRET_SENTINEL"}"#,
        ] {
            assert!(serde_json::from_str::<FailureOutcome>(message).is_err());
        }
    }
}
