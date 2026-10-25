//! Pinned SSH sessions and remote failure reporting.
use std::{path::Path, time::Duration};

use anyhow::{Result, ensure};
use tokio::process::Command;

use super::{
    Diagnostic, Request,
    command::{Output, execute, isolated_command},
};

pub(super) struct Ssh<'a> {
    pub(super) request: &'a Request,
    pub(super) home: &'a Path,
    pub(super) key: &'a Path,
    pub(super) known_hosts: &'a Path,
    pub(super) host_algorithm: &'a str,
}

impl Ssh<'_> {
    fn command(&self) -> Command {
        let mut command = isolated_command("ssh", self.home);
        command.args([
            "-F",
            "/dev/null",
            "-T",
            "-4",
            "-p",
            &self.request.ssh_port.to_string(),
            "-l",
            &self.request.ssh_user,
        ]);
        command.arg("-i").arg(self.key);

        for option in [
            "BatchMode=yes",
            "IdentitiesOnly=yes",
            "IdentityAgent=none",
            "AddKeysToAgent=no",
            "StrictHostKeyChecking=yes",
            "GlobalKnownHostsFile=/dev/null",
            "UpdateHostKeys=no",
            "VerifyHostKeyDNS=no",
            "CheckHostIP=no",
            "PasswordAuthentication=no",
            "KbdInteractiveAuthentication=no",
            "PreferredAuthentications=publickey",
            "PubkeyAuthentication=yes",
            "HostbasedAuthentication=no",
            "GSSAPIAuthentication=no",
            "ForwardAgent=no",
            "ForwardX11=no",
            "ClearAllForwardings=yes",
            "ControlMaster=no",
            "ControlPath=none",
            "ProxyCommand=none",
            "ProxyJump=none",
            "ConnectTimeout=10",
            "ConnectionAttempts=1",
            "ServerAliveInterval=10",
            "ServerAliveCountMax=2",
            "LogLevel=ERROR",
        ] {
            command.arg("-o").arg(option);
        }

        command
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.known_hosts.display()));
        command
            .arg("-o")
            .arg(format!("HostKeyAlgorithms={}", self.host_algorithm));
        command.arg(self.request.address.to_string());
        // Only a constant remote command appears in argv. Secrets and the
        // strictly quoted script travel over encrypted stdin, never argv.
        command.arg("if [ \"$(id -u)\" -eq 0 ]; then exec /usr/bin/timeout 380 /bin/bash -s; else exec sudo -n /usr/bin/timeout 380 /bin/bash -s; fi");

        command
    }

    pub(super) async fn script(&self, script: &str, duration: Duration) -> Result<String> {
        let output = execute(self.command(), script.as_bytes(), duration).await?;

        checked_output(output)
    }
}

fn checked_output(output: Output) -> Result<String> {
    if !output.success {
        if output
            .stderr
            .contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
            || output.stderr.contains("Host key verification failed")
        {
            return Err(Diagnostic::SshHostKeyMismatch.into());
        }

        for line in output.stdout.lines().chain(output.stderr.lines()) {
            if let Some(code) = line.strip_prefix("TUNNELLB_ERROR ") {
                if let Some(diagnostic) = Diagnostic::from_remote_marker(code) {
                    return Err(diagnostic.into());
                }

                return Err(Diagnostic::RemoteFailed.into());
            }
        }

        let diagnostic = [
            ("Load key ", Diagnostic::SshKeyInvalid),
            ("Permission denied", Diagnostic::SshAuthentication),
            ("Connection refused", Diagnostic::SshConnectionRefused),
            ("No route to host", Diagnostic::SshUnreachable),
            ("Network is unreachable", Diagnostic::SshUnreachable),
            ("Connection timed out", Diagnostic::SshTimeout),
            ("Connection closed", Diagnostic::SshConnectionClosed),
            ("Connection reset", Diagnostic::SshConnectionClosed),
            ("no matching ", Diagnostic::SshNegotiation),
            ("sudo:", Diagnostic::RemoteSudo),
        ]
        .into_iter()
        .find_map(|(pattern, diagnostic)| output.stderr.contains(pattern).then_some(diagnostic))
        .unwrap_or(Diagnostic::RemoteFailed);

        return Err(diagnostic.into());
    }

    ensure!(
        output.stdout.lines().any(|line| line == "TUNNELLB_OK"),
        Diagnostic::RemoteOutput
    );

    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision::{Operation, test_support::request};

    #[test]
    fn remote_markers_produce_typed_errors_without_remote_output() {
        for (code, diagnostic) in [
            ("firewall-inspection", Diagnostic::FirewallInspection),
            ("firewall-configuration", Diagnostic::FirewallConfiguration),
            ("firewall-cleanup", Diagnostic::FirewallCleanup),
            ("firewall-unavailable", Diagnostic::FirewallUnavailable),
            ("control-unreachable", Diagnostic::ControlUnreachable),
        ] {
            for stderr in [false, true] {
                let marker = format!("SECRET_SENTINEL\nTUNNELLB_ERROR {code}\n");
                let error = checked_output(Output {
                    success: false,
                    stdout: if stderr {
                        String::new()
                    } else {
                        marker.clone()
                    },
                    stderr: if stderr { marker } else { String::new() },
                })
                .unwrap_err();
                assert_eq!(error.downcast_ref::<Diagnostic>(), Some(&diagnostic));
                assert!(!format!("{error:?}").contains("SECRET_SENTINEL"));
            }
        }
    }

    #[test]
    fn sudo_failure_survives_the_worker_result_boundary() {
        let error = checked_output(Output {
            success: false,
            stdout: "TUNNELLB_ERROR sudo\n".into(),
            stderr: "SECRET_SENTINEL".into(),
        })
        .unwrap_err();
        let failure = crate::provision::FailureOutcome::from_error(&error);
        assert!(failure.error.to_string().contains("noninteractive sudo"));
        assert!(!failure.error.to_string().contains("SECRET_SENTINEL"));
    }

    #[test]
    fn ssh_failures_report_actionable_causes_without_echoing_stderr() {
        for (stderr, expected) in [
            (
                "Permission denied (publickey).",
                Diagnostic::SshAuthentication,
            ),
            (
                "connect to host: Connection refused",
                Diagnostic::SshConnectionRefused,
            ),
            ("No route to host", Diagnostic::SshUnreachable),
            ("Connection timed out", Diagnostic::SshTimeout),
            (
                "Host key verification failed.",
                Diagnostic::SshHostKeyMismatch,
            ),
            (
                "Load key SECRET_SENTINEL: invalid format\nPermission denied",
                Diagnostic::SshKeyInvalid,
            ),
            ("sudo: a password is required", Diagnostic::RemoteSudo),
            ("unrecognized failure", Diagnostic::RemoteFailed),
        ] {
            let error = checked_output(Output {
                success: false,
                stdout: String::new(),
                stderr: format!("{stderr}\nSECRET_SENTINEL"),
            })
            .unwrap_err();
            let failure = crate::provision::FailureOutcome::from_error(&error);
            let encoded = serde_json::to_string(&failure).unwrap();
            let decoded: crate::provision::FailureOutcome = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded.error, expected);
            assert!(!decoded.error.to_string().contains("SECRET_SENTINEL"));
            assert!(!encoded.contains("SECRET_SENTINEL"));
        }
    }

    #[test]
    fn remote_codes_must_match_exactly_and_never_echo_unknown_data() {
        for code in ["SECRET_SENTINEL", "firewall-inspection SECRET_SENTINEL"] {
            let error = checked_output(Output {
                success: false,
                stdout: format!("TUNNELLB_ERROR {code}\n"),
                stderr: "SECRET_SENTINEL".into(),
            })
            .unwrap_err();
            assert_eq!(
                error.downcast_ref::<Diagnostic>(),
                Some(&Diagnostic::RemoteFailed),
            );
            assert!(!format!("{error:#}").contains("SECRET_SENTINEL"));
        }
    }

    #[tokio::test]
    async fn ssh_configuration_disables_other_identity_and_trust_sources() {
        let request = request(Operation::Enroll);
        std::fs::create_dir_all("/tmp/codex").unwrap();
        let home = tempfile::tempdir_in("/tmp/codex").unwrap();
        let ssh = Ssh {
            request: &request,
            home: home.path(),
            key: &home.path().join("identity"),
            known_hosts: &home.path().join("known_hosts"),
            host_algorithm: "ssh-ed25519",
        };

        let command = ssh.command();
        let mut configuration = isolated_command("ssh", home.path());
        configuration.arg("-G").args(command.as_std().get_args());
        let output = execute(configuration, &[], Duration::from_secs(2))
            .await
            .unwrap();
        assert!(output.success);

        for required in [
            "stricthostkeychecking true",
            "globalknownhostsfile /dev/null",
            "updatehostkeys false",
            "identityagent none",
            "identitiesonly yes",
            "forwardagent no",
            "passwordauthentication no",
            "kbdinteractiveauthentication no",
            "hostkeyalgorithms ssh-ed25519",
        ] {
            assert!(
                output.stdout.lines().any(|line| line == required),
                "{required}"
            );
        }

        assert!(
            output.stdout.lines().any(|line| {
                line == format!("userknownhostsfile {}", ssh.known_hosts.display())
            })
        );
    }
}
