//! Pod-local egress enforcement and supervision of the pinned FRP client.
//!
//! The filter runs before host-side Service DNAT on the supported veth /
//! kube-proxy iptables path. CNI socket-level Service translation is not supported:
//! the default DROP then prevents forwarding rather than broadening access.

use std::{
    fs,
    io::{self, Read},
    path::Path,
};

use anyhow::{Result, ensure};

mod guard;
mod readiness;
mod supervision;

pub use guard::{AllowedDestination, GuardConfig, apply_allow, apply_guard};
pub use readiness::ready;
pub use supervision::run;

pub const READY_PATH: &str = "/tmp/tunnellb-ready";
pub const ALIVE_PATH: &str = "/tmp/tunnellb-alive";
pub const GUARD_MARKER: &str = "/tmp/tunnellb-guard-installed";
const MAX_CONFIG_BYTES: usize = 1_048_576;

fn bounded_file(path: &Path) -> Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_CONFIG_BYTES,
        "configuration exceeds size limit"
    );
    Ok(bytes)
}

fn remove_marker(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
