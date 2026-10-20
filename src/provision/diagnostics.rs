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
            Self::WorkerFailed => "SSHFailed",
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
