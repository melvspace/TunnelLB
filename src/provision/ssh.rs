//! Pinned SSH sessions and remote failure reporting.
use std::{path::Path, time::Duration};

use anyhow::{Result, bail, ensure};
use tokio::process::Command;

use super::{
    Request,
    command::{execute, isolated_command},
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

        if !output.success {
            if output
                .stderr
                .contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
                || output.stderr.contains("Host key verification failed")
            {
                bail!(
                    "SSH host key does not match the stored pin; investigate the host change and explicitly re-enroll, never silently re-trust it"
                );
            }

            for line in output.stdout.lines().chain(output.stderr.lines()) {
                if let Some(code) = line.strip_prefix("TUNNELLB_ERROR ") {
                    bail!("{}", remote_error(code));
                }
            }

            bail!(
                "remote provisioning failed; verify SSH reachability, the authorized private key and root or passwordless sudo access; remote cleanup may remain pending"
            );
        }

        ensure!(
            output.stdout.lines().any(|line| line == "TUNNELLB_OK"),
            "remote worker returned no valid success marker"
        );

        Ok(output.stdout)
    }
}

fn remote_error(code: &str) -> &'static str {
    match code {
        "sudo" => "SSH account requires root or noninteractive sudo access",
        "platform" => "external host must run Debian or Ubuntu with systemd as PID 1",
        "platform-version" => {
            "FRP hardening requires systemd 244 or newer; upgrade the dedicated host"
        }

        "architecture" => "external host architecture must be amd64 or arm64",
        "prerequisites" => {
            "external host is missing required system tools; install iproute2, util-linux and coreutils"
        }

        "dedicated-host" => {
            "external host appears to have k3s or Tailscale installed; use a dedicated host outside the cluster and its VPN"
        }

        "owner" => {
            "host ownership marker is absent or belongs to another Server UID; refusing takeover"
        }

        "legacy-layout" => {
            "legacy single-owner TunnelLB layout detected; uninstall with the old worker and explicitly reset its retained ownership markers before shared-host enrollment"
        }

        "server-revoked" => {
            "Server UID was uninstalled; explicit administrator ownership reset is required before re-enrollment"
        }

        "generation-revoked" => {
            "publication credential generation was revoked; delayed Apply cannot restore it"
        }

        "generation-conflict" => {
            "publication has a different reserved credential generation or configuration; remove it before applying replacement credentials"
        }

        "generation-state" => {
            "publication generation ownership is missing or malformed; refusing ambiguous cleanup or replacement"
        }

        "claim-state" => {
            "host-wide port claim is missing or malformed; restore owned reservation state before retrying"
        }

        "reservation-required" => "publication must reserve host-wide ports before Apply",
        "socket-state" => "host socket inspection returned malformed numeric listener state",
        "reservation-conflict" => {
            "publication reservation has different credentials or ports; remove it before reserving a replacement"
        }

        "account-owner" => {
            "FRP system account conflicts with an existing account; refusing to reuse it"
        }

        "unit-owner" => {
            "FRP systemd unit or drop-in is not owned or has changed; restore owned configuration before retrying"
        }

        "unsafe-path" => {
            "owned host path has an unexpected owner, type or symlink; refusing unsafe modification"
        }

        "busy" => "another TunnelLB worker owns the remote provisioning lock; retry later",
        "checksum" => {
            "remote FRP checksum does not match the immutable pinned binary; administrator repair is required"
        }

        "configuration" => {
            "FRP rejected the staged server configuration; check the publication and stored credentials"
        }

        "occupied-port" => {
            "a requested public or control port is occupied outside this publication; select unused ports"
        }

        "start" => {
            "owned FRP unit failed to start; inspect its systemd journal and verify certificates and port availability"
        }

        "stop" => "owned FRP unit could not be stopped; remote cleanup remains pending",
        _ => {
            "remote provisioning command failed; check host prerequisites and owned paths; remote cleanup may remain pending"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision::{Operation, test_support::request};

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
