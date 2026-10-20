use std::{
    collections::BTreeSet,
    fs,
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
    process::Stdio,
    time::Duration,
};

#[cfg(not(target_os = "linux"))]
use anyhow::bail;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, process::Command, time::timeout};

use super::{GUARD_MARKER, bounded_file, remove_marker};
use crate::api::{Protocol, Publication};

#[cfg(test)]
#[path = "guard_tests.rs"]
mod tests;

const GUARD_CHAIN: &str = "TUNNELLB_EGRESS";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllowedDestination {
    pub address: Ipv4Addr,
    pub port: u16,
    pub protocol: Protocol,
}

/// A literal IPv4 allowlist. There are deliberately no CIDRs, DNS names, shell
/// fragments, port ranges, or "established" exemptions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuardConfig {
    pub allowed: Vec<AllowedDestination>,
}

impl GuardConfig {
    pub fn for_publication(publication: &Publication) -> Self {
        let mut allowed = vec![AllowedDestination {
            address: publication.machine_address,
            port: publication.control_port,
            protocol: Protocol::Tcp,
        }];
        allowed.extend(
            publication
                .service
                .ports
                .iter()
                .map(|port| AllowedDestination {
                    address: publication.service.cluster_ip,
                    port: port.port,
                    protocol: port.protocol,
                }),
        );

        Self { allowed }
    }

    pub fn for_ssh(address: SocketAddrV4) -> Self {
        Self {
            allowed: vec![AllowedDestination {
                address: *address.ip(),
                port: address.port(),
                protocol: Protocol::Tcp,
            }],
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.allowed.is_empty(),
            "guard allowlist must not be empty"
        );
        ensure!(
            self.allowed.len() <= 1024,
            "guard allowlist exceeds 1024 entries"
        );

        for destination in &self.allowed {
            let address = destination.address;
            ensure!(
                !address.is_unspecified()
                    && !address.is_loopback()
                    && !address.is_multicast()
                    && !address.is_broadcast()
                    && !address.is_link_local()
                    && address.octets()[0] != 0
                    && address.octets()[0] < 224,
                "guard destination must be a unicast IPv4 address"
            );
            ensure!(
                destination.port > 0,
                "guard destination port must be nonzero"
            );
        }

        Ok(())
    }

    /// Input for iptables-restore --noflush. Only our dedicated chain is flushed;
    /// unrelated chains and OUTPUT rules are preserved. A first-position jump
    /// prevents an existing ACCEPT from bypassing our terminal DROP.
    pub fn ipv4_rules(&self) -> Result<String> {
        self.validate()?;
        let mut rules = guard_prefix();
        let destinations: BTreeSet<_> = self
            .allowed
            .iter()
            .map(|d| (d.address, d.protocol, d.port))
            .collect();

        for (address, protocol, port) in destinations {
            rules.push_str(&format!(
                "-A {GUARD_CHAIN} -d {address}/32 -p {} --dport {port} -j ACCEPT\n",
                protocol.frp_name()
            ));
        }

        finish_rules(&mut rules);
        Ok(rules)
    }

    pub fn ipv6_rules(&self) -> Result<String> {
        self.validate()?;
        let mut rules = guard_prefix();
        finish_rules(&mut rules);
        Ok(rules)
    }
}

fn guard_prefix() -> String {
    format!("*filter\n:{GUARD_CHAIN} - [0:0]\n-F {GUARD_CHAIN}\n")
}

fn finish_rules(rules: &mut String) {
    rules.push_str(&format!(
        "-A {GUARD_CHAIN} -j DROP\n-I OUTPUT 1 -j {GUARD_CHAIN}\nCOMMIT\n"
    ));
}

pub async fn apply_guard(config: &Path) -> Result<()> {
    let bytes = bounded_file(config)?;
    let config: GuardConfig =
        serde_json::from_slice(&bytes).context("invalid egress guard JSON")?;

    install_guard(&config).await
}

/// `guard --allow <IPv4>:<port>` uses precisely one TCP destination for SSH.
pub async fn apply_allow(address: SocketAddrV4) -> Result<()> {
    install_guard(&GuardConfig::for_ssh(address)).await
}

const RESTORE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn program(self) -> &'static str {
        match self {
            Self::V4 => "/usr/sbin/iptables-restore",
            Self::V6 => "/usr/sbin/ip6tables-restore",
        }
    }
}

// Test both families first, then deny IPv6 before installing IPv4 allowances.
// A failure never writes the installation marker or starts an application.
const INSTALL_STEPS: [(Family, bool); 4] = [
    (Family::V6, true),
    (Family::V4, true),
    (Family::V6, false),
    (Family::V4, false),
];

async fn install_guard(config: &GuardConfig) -> Result<()> {
    let ipv4 = config.ipv4_rules()?;
    let ipv6 = config.ipv6_rules()?;
    let namespace = guard_environment()?;
    remove_marker(Path::new(GUARD_MARKER))?;

    for (family, dry_run) in INSTALL_STEPS {
        let rules = if family == Family::V4 { &ipv4 } else { &ipv6 };
        restore(family, dry_run, rules).await?;
    }

    write_guard_marker(&namespace)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn guard_environment() -> Result<String> {
    // Kubernetes starts our binary directly as init-container PID 1. Combined
    // with the downward API identity this rejects accidental execution on a
    // workstation/host. The builder's hostNetwork=false/hostPID=false are the
    // actual namespace boundary; this check is not an admission policy.
    ensure!(
        std::process::id() == 1,
        "guard must be the pod init-container PID 1"
    );

    // SAFETY: geteuid has no arguments or memory effects.
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "guard requires init-container root"
    );

    let uid = std::env::var("TUNNELLB_POD_UID").context("missing downward API pod UID")?;
    ensure!(
        !uid.is_empty()
            && uid.len() <= 128
            && uid.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid downward API pod UID"
    );

    let status = fs::read_to_string("/proc/self/status")?;
    let caps = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .context("missing Linux capability state")?;
    ensure!(
        u64::from_str_radix(caps, 16)? == 1 << 12,
        "guard requires exactly CAP_NET_ADMIN, with all other capabilities dropped"
    );
    ensure!(
        status.lines().any(|line| line == "NoNewPrivs:\t1"),
        "guard requires no-new-privileges"
    );

    net_namespace()
}

#[cfg(not(target_os = "linux"))]
fn guard_environment() -> Result<String> {
    bail!("egress guard requires Linux pod networking")
}

fn net_namespace() -> Result<String> {
    let namespace = fs::read_link("/proc/self/ns/net")?;
    let namespace = namespace
        .to_str()
        .context("invalid network namespace identity")?;
    ensure!(
        namespace.starts_with("net:[") && namespace.ends_with(']'),
        "unsupported network namespace"
    );
    Ok(namespace.to_owned())
}

async fn restore(family: Family, dry_run: bool, rules: &str) -> Result<()> {
    let mut command = Command::new(family.program());
    command.args(["--wait", "5", "--noflush"]);

    if dry_run {
        command.arg("--test");
    }

    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .context("cannot execute required iptables restore tool")?;
    let mut stdin = child.stdin.take().context("missing restore stdin")?;
    let operation = async {
        stdin.write_all(rules.as_bytes()).await?;
        stdin.shutdown().await?;
        drop(stdin);

        let status = child.wait().await?;
        ensure!(
            status.success(),
            "egress guard restore failed for {family:?}"
        );
        Ok::<_, anyhow::Error>(())
    };
    timeout(RESTORE_TIMEOUT, operation)
        .await
        .context("egress guard restore timed out")??;
    Ok(())
}

#[cfg(unix)]
fn write_guard_marker(namespace: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(GUARD_MARKER)?;
    file.write_all(namespace.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_guard_marker(_: &str) -> Result<()> {
    bail!("egress guard requires Linux")
}

pub(super) fn verify_guard_marker() -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = fs::symlink_metadata(GUARD_MARKER)
            .context("pod egress guard has not been installed")?;
        ensure!(
            metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o222 == 0,
            "invalid egress guard installation marker"
        );
    }

    ensure!(
        fs::read_to_string(GUARD_MARKER)? == net_namespace()?,
        "egress guard belongs to a different network namespace"
    );
    Ok(())
}
