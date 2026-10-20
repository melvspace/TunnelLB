use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    env, fs,
    io::Write,
    net::Ipv4Addr,
    path::PathBuf,
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(super) const BASE: &str = "/tmp/codex/tunnellb-e2e";

pub(super) fn enabled(name: &str) -> bool {
    env::var(name).as_deref() == Ok("1")
}

/// Commands have an external deadline as well as Kubernetes request timeouts.
/// Never include submitted objects or command output in generic errors: some
/// calls transport Secret values through stdin or stdout.
pub(super) fn execute(
    program: &str,
    args: &[&str],
    input: Option<&[u8]>,
    seconds: u64,
) -> Result<Output> {
    let mut command = Command::new("timeout");
    command
        .args([
            "--signal=TERM",
            "--kill-after=5s",
            &format!("{seconds}s"),
            program,
        ])
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Helm accepts API and credential overrides independently of --kubeconfig.
    // The only cluster selection for these processes is our explicit config.
    for (key, _) in env::vars_os() {
        if key.to_string_lossy().starts_with("HELM_KUBE") {
            command.env_remove(key);
        }
    }

    for key in [
        "KUBECONFIG",
        "KUBERNETES_MASTER",
        "HELM_DRIVER",
        "HELM_DRIVER_SQL_CONNECTION_STRING",
    ] {
        command.env_remove(key);
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("could not start {program}"))?;

    if let Some(input) = input {
        child
            .stdin
            .take()
            .context("missing command stdin")?
            .write_all(input)?;
    }

    Ok(child.wait_with_output()?)
}

pub(super) fn checked(
    program: &str,
    args: &[&str],
    input: Option<&[u8]>,
    seconds: u64,
) -> Result<Vec<u8>> {
    let output = execute(program, args, input, seconds)?;
    ensure!(
        output.status.success(),
        "{program} failed with {} (output withheld)",
        output.status
    );

    Ok(output.stdout)
}

pub(super) fn text(bytes: Vec<u8>) -> Result<String> {
    Ok(String::from_utf8(bytes)?.trim().to_owned())
}

pub(super) struct Environment {
    pub(super) kubeconfig: String,
    pub(super) context: String,
    pub(super) cluster: String,
    pub(super) k3d: String,
    pub(super) edge: String,
    pub(super) address: Ipv4Addr,
    pub(super) key: PathBuf,
    pub(super) authorized_keys_digest: String,
}

impl Environment {
    pub(super) fn load() -> Result<Self> {
        Self::load_cluster("TUNNELLB_E2E_KUBECONFIG", "TUNNELLB_E2E_CLUSTER")
    }

    pub(super) fn load_second() -> Result<Self> {
        ensure!(
            env::var("TUNNELLB_E2E_SECOND_CLUSTER").is_ok(),
            "explicit second disposable cluster required"
        );
        ensure!(
            env::var("TUNNELLB_E2E_FIXTURE").is_ok(),
            "explicit shared fixture ownership label required"
        );

        Self::load_cluster(
            "TUNNELLB_E2E_SECOND_KUBECONFIG",
            "TUNNELLB_E2E_SECOND_CLUSTER",
        )
    }

    fn load_cluster(kubeconfig_variable: &str, cluster_variable: &str) -> Result<Self> {
        ensure!(
            enabled("TUNNELLB_E2E_ALLOW_DESTRUCTIVE"),
            "set TUNNELLB_E2E_ALLOW_DESTRUCTIVE=1 for the disposable local environment"
        );
        let kubeconfig = fs::canonicalize(
            env::var(kubeconfig_variable).context("explicit isolated kubeconfig required")?,
        )?;
        ensure!(
            kubeconfig.starts_with("/tmp/codex/"),
            "kubeconfig must resolve under /tmp/codex"
        );
        let cluster = env::var(cluster_variable).unwrap_or_else(|_| "tunnellb-e2e".into());
        let fixture = env::var("TUNNELLB_E2E_FIXTURE").unwrap_or_else(|_| cluster.clone());
        ensure!(
            cluster.starts_with("tunnellb-e2e")
                && cluster
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "unexpected cluster name"
        );
        let edge =
            env::var("TUNNELLB_E2E_EDGE_CONTAINER").unwrap_or_else(|_| "tunnellb-e2e-edge".into());
        let inspection: Value =
            serde_json::from_slice(&checked("docker", &["inspect", &edge], None, 15)?)?;
        ensure!(
            inspection[0]["Config"]["Labels"]["tunnellb.io/e2e"] == fixture,
            "edge container is not owned by this test environment"
        );
        ensure!(
            inspection[0]["HostConfig"]["CgroupnsMode"] == "private",
            "edge requires private cgroups"
        );
        ensure!(
            inspection[0]["HostConfig"]["PidMode"] != "host",
            "host PID namespace forbidden"
        );
        ensure!(
            inspection[0]["Mounts"]
                .as_array()
                .is_some_and(Vec::is_empty),
            "prepared edge must not mount host paths"
        );
        let networks = inspection[0]["NetworkSettings"]["Networks"]
            .as_object()
            .context("edge networks missing")?;
        ensure!(
            networks.len() == 1,
            "edge must use only its dedicated network"
        );
        let (network, connection) = networks.iter().next().unwrap();
        let net: Value = serde_json::from_slice(&checked(
            "docker",
            &["network", "inspect", network],
            None,
            15,
        )?)?;
        ensure!(
            net[0]["Labels"]["tunnellb.io/e2e"] == fixture,
            "network ownership mismatch"
        );
        let address: Ipv4Addr = connection["IPAddress"]
            .as_str()
            .context("edge IP missing")?
            .parse()?;
        let key = fs::canonicalize(
            env::var("TUNNELLB_E2E_SSH_KEY").unwrap_or_else(|_| format!("{BASE}/ssh/id_ed25519")),
        )?;
        ensure!(
            key.starts_with("/tmp/codex/"),
            "test SSH key must resolve under /tmp/codex"
        );
        let authorized_keys_digest = text(checked(
            "docker",
            &["exec", &edge, "sha256sum", "/root/.ssh/authorized_keys"],
            None,
            15,
        )?)?;
        let result = Self {
            kubeconfig: kubeconfig
                .to_str()
                .context("invalid kubeconfig path")?
                .into(),
            context: format!("k3d-{cluster}"),
            cluster,
            k3d: env::var("TUNNELLB_E2E_K3D").unwrap_or_else(|_| format!("{BASE}/bin/k3d")),
            edge,
            address,
            key,
            authorized_keys_digest,
        };
        let config = result.json(&["config", "view", "--minify", "-o", "json"])?;
        ensure!(
            config["clusters"][0]["cluster"]["server"]
                .as_str()
                .and_then(|s| s.strip_prefix("https://127.0.0.1:"))
                .and_then(|port| port.parse::<u16>().ok())
                .is_some_and(|port| port != 0),
            "API must be bound to loopback"
        );
        let nodes = result.json(&["get", "nodes", "-o", "json"])?;
        let nodes = nodes["items"].as_array().context("nodes missing")?;
        ensure!(!nodes.is_empty(), "cluster has no nodes");

        for node in nodes {
            ensure!(
                node["metadata"]["name"]
                    .as_str()
                    .is_some_and(|n| n.starts_with(&format!("k3d-{}-", result.cluster))),
                "unexpected Kubernetes node"
            );
            let conditions = node["status"]["conditions"]
                .as_array()
                .context("node conditions missing")?;
            ensure!(
                conditions
                    .iter()
                    .any(|condition| condition["type"] == "Ready" && condition["status"] == "True")
                    && conditions
                        .iter()
                        .any(|condition| condition["type"] == "DiskPressure"
                            && condition["status"] == "False"),
                "disposable nodes must be Ready without DiskPressure"
            );
            ensure!(
                !node["status"]["addresses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| a["address"] == address.to_string()),
                "edge cannot be a Kubernetes node"
            );
        }

        let server: Value = serde_json::from_slice(&checked(
            "docker",
            &["inspect", &format!("k3d-{}-server-0", result.cluster)],
            None,
            15,
        )?)?;
        ensure!(
            server[0]["Config"]["Labels"]["tunnellb.io/e2e"] == fixture
                && server[0]["NetworkSettings"]["Networks"]
                    .get(network)
                    .is_some(),
            "cluster server must belong to this disposable fixture and network"
        );
        ensure!(
            server[0]["Config"]["Cmd"]
                .as_array()
                .is_some_and(|args| args.iter().any(|arg| arg == "--disable=servicelb")),
            "ServiceLB must be disabled in the disposable test cluster"
        );
        ensure!(
            text(result.docker(&["systemctl", "is-system-running"])?)? == "running",
            "edge systemd is not running"
        );

        Ok(result)
    }

    pub(super) fn kubectl(&self, args: &[&str]) -> Result<Vec<u8>> {
        let mut all = vec![
            "--kubeconfig",
            &self.kubeconfig,
            "--context",
            &self.context,
            "--request-timeout=15s",
        ];
        all.extend_from_slice(args);

        checked("kubectl", &all, None, 180)
    }

    pub(super) fn json(&self, args: &[&str]) -> Result<Value> {
        Ok(serde_json::from_slice(&self.kubectl(args)?)?)
    }

    pub(super) fn apply(&self, object: &Value) -> Result<()> {
        checked(
            "kubectl",
            &[
                "--kubeconfig",
                &self.kubeconfig,
                "--context",
                &self.context,
                "--request-timeout=15s",
                "apply",
                "-f",
                "-",
            ],
            Some(&serde_json::to_vec(object)?),
            30,
        )?;

        Ok(())
    }

    pub(super) fn docker(&self, args: &[&str]) -> Result<Vec<u8>> {
        let mut all = vec!["exec", &self.edge];
        all.extend_from_slice(args);

        checked("docker", &all, None, 30)
    }
}

pub(super) fn wait_for(
    label: &str,
    seconds: u64,
    mut condition: impl FnMut() -> Result<bool>,
) -> Result<()> {
    let end = Instant::now() + Duration::from_secs(seconds);

    loop {
        if condition()? {
            return Ok(());
        }

        ensure!(Instant::now() < end, "timed out waiting for {label}");
        thread::sleep(Duration::from_secs(2));
    }
}
