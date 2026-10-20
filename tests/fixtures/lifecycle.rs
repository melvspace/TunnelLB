use crate::{
    cluster::{execute, text, wait_for},
    publication::{connect, exchange},
    setup::Run,
};
use anyhow::{Context, Result, ensure};
use std::{
    thread,
    time::{Duration, Instant},
};

impl Run {
    pub(super) fn lifecycle(&self) -> Result<()> {
        eprintln!("e2e: conflicts, PROXY v2, backend and controller restarts");

        let before = self.connector("echo")?;
        let selector = format!(
            "tunnellb.io/publication={}",
            before["metadata"]["name"].as_str().unwrap()
        );
        let pods = self.list(&self.operator, "pods", &selector)?;
        let pod_uid = pods
            .iter()
            .find(|p| p["spec"]["containers"][0]["name"] == "connector")
            .context("connector Pod missing")?["metadata"]["uid"]
            .clone();

        self.env
            .apply(&self.service("conflict", 18080, 18081, false))?;
        wait_for("port collision rejection", 30, || {
            Ok(
                self.get(&self.app, "service", "conflict")?["status"]["conditions"]
                    .as_array()
                    .is_some_and(|cs| cs.iter().any(|c| c["reason"] == "AllocationPending")),
            )
        })?;
        ensure!(
            self.get(&self.app, "service", "conflict")?["status"]["loadBalancer"]["ingress"]
                .as_array()
                .is_none_or(Vec::is_empty)
        );
        self.traffic(18080, 18081, false)?;
        self.env.kubectl(&[
            "-n",
            &self.app,
            "delete",
            "service",
            "conflict",
            "--wait=true",
            "--timeout=60s",
        ])?;

        self.env.apply(&self.service("proxy", 18082, 18083, true))?;
        self.published("proxy")?;
        self.traffic(18082, 18083, true)?;

        // Sending an arbitrary destination request through an outsider's public
        // socket remains application payload at the fixed approved backend.
        let mut stream = connect(self.env.address, 18080)?;
        let request = "CONNECT 10.43.0.1:443 HTTP/1.1";
        ensure!(
            exchange(&mut stream, request)?["payload"] == request,
            "outsider payload escaped the configured backend"
        );

        self.env
            .kubectl(&["-n", &self.app, "rollout", "restart", "deployment/backend"])?;
        self.env.kubectl(&[
            "-n",
            &self.app,
            "rollout",
            "status",
            "deployment/backend",
            "--timeout=120s",
        ])?;
        self.published("echo")?;
        thread::sleep(Duration::from_secs(5));

        ensure!(
            self.connector("echo")?["metadata"]["uid"] == before["metadata"]["uid"],
            "backend rollout replaced connector Deployment"
        );
        ensure!(
            self.list(&self.operator, "pods", &selector)?
                .iter()
                .any(|p| p["metadata"]["uid"] == pod_uid),
            "backend rollout restarted connector Pod"
        );
        self.traffic(18080, 18081, false)?;

        self.env.kubectl(&[
            "-n",
            &self.operator,
            "rollout",
            "restart",
            "deployment/tunnellb-controller",
        ])?;
        self.env.kubectl(&[
            "-n",
            &self.operator,
            "rollout",
            "status",
            "deployment/tunnellb-controller",
            "--timeout=120s",
        ])?;

        thread::sleep(Duration::from_secs(5));
        self.published("echo")?;
        self.traffic(18080, 18081, false)?;

        ensure!(
            self.connector("echo")?["metadata"]["uid"] == before["metadata"]["uid"],
            "controller restart replaced connector Deployment"
        );
        ensure!(
            self.list(&self.operator, "pods", &selector)?
                .iter()
                .any(|p| p["metadata"]["uid"] == pod_uid),
            "controller restart restarted connector Pod"
        );

        Ok(())
    }

    pub(super) fn deletion(&self) -> Result<()> {
        eprintln!("e2e: deletion revokes active TCP and removes owned remote files/units");

        let machine = self.get(&self.operator, "machine", &self.machine)?;
        let uid = machine["metadata"]["uid"].as_str().unwrap();
        let deployment = self.connector("echo")?;
        let publication = deployment["metadata"]["name"].as_str().unwrap();
        let unit = format!("tunnellb-{uid}@{publication}.service");
        ensure!(text(self.env.docker(&["systemctl", "is-active", &unit])?)? == "active");

        let mut connection = connect(self.env.address, 18080)?;
        let first = exchange(&mut connection, "before-delete")?;

        self.env
            .kubectl(&["-n", &self.app, "delete", "service", "echo", "--wait=false"])?;

        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match exchange(&mut connection, "still-open") {
                Ok(reply) => ensure!(
                    reply["connection_id"] == first["connection_id"],
                    "test connection changed"
                ),
                Err(error) => match error.downcast_ref::<std::io::Error>() {
                    Some(io)
                        if matches!(
                            io.kind(),
                            std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::BrokenPipe
                                | std::io::ErrorKind::NotConnected
                        ) =>
                    {
                        break;
                    }
                    _ => return Err(error.context("TCP closure was not confirmed")),
                },
            }

            ensure!(
                Instant::now() < deadline,
                "existing TCP session survived Service deletion"
            );
            thread::sleep(Duration::from_secs(1));
        }

        self.env.kubectl(&[
            "-n",
            &self.app,
            "wait",
            "--for=delete",
            "service/echo",
            "--timeout=120s",
        ])?;

        let active = execute(
            "docker",
            &["exec", &self.env.edge, "systemctl", "is-active", &unit],
            None,
            15,
        )?;
        ensure!(
            !active.status.success(),
            "deleted publication unit still active"
        );
        self.env.docker(&[
            "test",
            "!",
            "-e",
            &format!("/var/lib/tunnellb/{uid}/publications/{publication}"),
        ])?;

        self.env.kubectl(&[
            "-n",
            &self.app,
            "delete",
            "service",
            "proxy",
            "--wait=true",
            "--timeout=120s",
        ])?;

        self.env.kubectl(&[
            "delete",
            "machine",
            &self.machine,
            "--cascade=foreground",
            "--wait=true",
            "--timeout=150s",
        ])?;

        self.env.docker(&[
            "test",
            "!",
            "-e",
            &format!("/etc/systemd/system/tunnellb-{uid}@.service"),
        ])?;
        self.env
            .docker(&["test", "!", "-e", &format!("/var/lib/tunnellb/{uid}")])?;
        ensure!(
            text(self.env.docker(&["cat", "/var/lib/tunnellb/uninstalled"])?)? == uid,
            "terminal Machine tombstone was not retained"
        );
        self.env
            .docker(&["test", "!", "-e", "/opt/tunnellb/0.71.1/frps"])?;

        ensure!(
            text(
                self.env
                    .docker(&["sha256sum", "/root/.ssh/authorized_keys"])?
            )? == self.env.authorized_keys_digest,
            "remote cleanup changed the original authorized SSH key"
        );
        ensure!(
            text(
                self.env
                    .docker(&["systemctl", "is-active", "e2e-unpublished.service"])?
            )? == "active",
            "cleanup removed an unrelated unit"
        );

        Ok(())
    }
}
