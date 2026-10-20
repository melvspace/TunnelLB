use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, ensure};

use super::remove_marker;

#[cfg(test)]
#[path = "readiness_tests.rs"]
mod tests;

const MARKER_MAX_AGE: Duration = Duration::from_secs(15);

/// An exec probe checks a marker that the supervisor refreshes every two
/// seconds. A dead/hung supervisor cannot leave a permanently healthy marker.
pub fn ready(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("connector is not ready")?;
    ensure!(metadata.is_file(), "readiness marker is not a regular file");
    let age = SystemTime::now().duration_since(metadata.modified()?)?;
    ensure!(age <= MARKER_MAX_AGE, "connector health marker is stale");
    Ok(())
}

pub(super) struct HealthMarkers {
    pub(super) ready: PathBuf,
    alive: PathBuf,
}

impl HealthMarkers {
    pub(super) fn new(ready: &Path) -> Result<Self> {
        let markers = Self {
            ready: ready.into(),
            alive: ready
                .parent()
                .unwrap_or(Path::new("/tmp"))
                .join("tunnellb-alive"),
        };
        ensure!(
            markers.ready != markers.alive,
            "readiness and liveness paths must differ"
        );
        remove_marker(&markers.ready)?;
        remove_marker(&markers.alive)?;
        Ok(markers)
    }

    pub(super) fn refresh(&self, registered: bool) -> Result<()> {
        fs::write(&self.alive, b"supervising\n")?;

        if registered {
            fs::write(&self.ready, b"registered\n")?;
        } else {
            remove_marker(&self.ready)?;
        }

        Ok(())
    }
}

impl Drop for HealthMarkers {
    fn drop(&mut self) {
        let _ = remove_marker(&self.ready);
        let _ = remove_marker(&self.alive);
    }
}

#[derive(Debug)]
pub(super) struct Registrations {
    expected: BTreeSet<String>,
    registered: BTreeSet<String>,
}

impl Registrations {
    pub(super) fn from_config(contents: &str) -> Result<Self> {
        let config: toml::Value = toml::from_str(contents).context("invalid FRP TOML")?;
        let log = config
            .get("log")
            .context("FRP console logging is required")?;
        ensure!(
            log.get("to").and_then(toml::Value::as_str) == Some("console")
                && log.get("level").and_then(toml::Value::as_str) == Some("debug")
                && log.get("disablePrintColor").and_then(toml::Value::as_bool) == Some(true),
            "FRP readiness requires debug console logging with color disabled"
        );

        // Generated configuration is immutable. Additional config sources
        // would make the expected registration set incomplete.
        for key in ["includes", "visitors", "start", "store", "webServer"] {
            ensure!(
                config.get(key).is_none(),
                "unsupported FRP dynamic configuration: {key}"
            );
        }

        let proxies = config
            .get("proxies")
            .and_then(toml::Value::as_array)
            .context("FRP configuration has no proxies")?;
        ensure!(
            !proxies.is_empty() && proxies.len() <= 1024,
            "invalid proxy count"
        );

        let mut expected = BTreeSet::new();

        for proxy in proxies {
            let name = proxy
                .get("name")
                .and_then(toml::Value::as_str)
                .context("proxy has no name")?;
            ensure!(
                !name.is_empty()
                    && name.len() <= 253
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
                "invalid proxy name"
            );
            ensure!(expected.insert(name.to_owned()), "duplicate proxy name");
            ensure!(
                matches!(
                    proxy.get("type").and_then(toml::Value::as_str),
                    Some("tcp" | "udp")
                ),
                "only TCP/UDP proxies are supported"
            );
            ensure!(
                proxy.get("healthCheck").is_none(),
                "FRP health checks are unsupported"
            );
        }

        Ok(Self {
            expected,
            registered: BTreeSet::new(),
        })
    }

    pub(super) fn ready(&self) -> bool {
        self.registered == self.expected
    }

    pub(super) fn observe(&mut self, line: &str) {
        // Verified against fatedier/frp v0.71.1 client/control.go and
        // client/service.go. Source + severity + exact success suffix prevent
        // arbitrary error text containing a proxy name from marking it ready.
        // Registration is the peer's acknowledgement, not an end-to-end probe.
        let control = source_line(line, "client/control.go:");
        let service = source_line(line, "client/service.go:");

        if (service.is_some()
            && (line.contains("try to connect to server...")
                || line.contains("login to server success")
                || line.contains("connect to server error:")
                || line.contains("login to the server failed")))
            || (control.is_some()
                && (line.contains("control message dispatcher exited")
                    || line.contains("heartbeat timeout")
                    || line.contains("pong message contains error:")))
        {
            self.registered.clear();

            return;
        }

        // FRP retries a rejected proxy without restarting successful siblings.
        // Removing all registrations here would require successes that FRP
        // will never re-emit until the control connection reconnects.
        if control == Some('W')
            && let Some((prefix, _)) = line.split_once("] start error:")
            && let Some((_, proxy)) = prefix.rsplit_once('[')
        {
            self.registered.remove(proxy);

            return;
        }

        if control == Some('I') {
            for proxy in &self.expected {
                if line
                    .trim_end()
                    .ends_with(&format!("[{proxy}] start proxy success"))
                {
                    self.registered.insert(proxy.clone());
                    break;
                }
            }
        }
    }
}

fn source_line(line: &str, source: &str) -> Option<char> {
    // Read the FIRST level/source header, never one embedded in remote error
    // text. FRP's timestamp has no brackets.
    let (_, header) = line.split_once(" [")?;
    let level = header.chars().next()?;

    if !matches!(level, 'I' | 'D' | 'W' | 'E') {
        return None;
    }

    let after_level = header.get(1..)?.strip_prefix("] [")?;
    let after_source = after_level.strip_prefix(source)?;
    let (line_number, _) = after_source.split_once(']')?;
    (!line_number.is_empty() && line_number.bytes().all(|b| b.is_ascii_digit())).then_some(level)
}
