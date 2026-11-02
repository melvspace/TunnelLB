//! Credential-free Prometheus text exposition. Callers supply fixed metric and
//! label names; values are Kubernetes identities or allowlisted outcomes.
use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    sync::{Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Samples = BTreeMap<String, f64>;

#[derive(Default)]
struct Registry {
    families: BTreeMap<&'static str, (&'static str, Samples)>,
    completed: VecDeque<String>,
}

static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(Mutex::default)
}

fn key(labels: &[(&str, &str)]) -> String {
    let labels = labels
        .iter()
        .map(|(name, value)| {
            let value = value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");

            format!("{name}=\"{value}\"")
        })
        .collect::<Vec<_>>()
        .join(",");

    format!("{{{labels}}}")
}

pub fn set(name: &'static str, labels: &[(&str, &str)], value: f64) {
    let mut registry = registry().lock().unwrap();
    registry
        .families
        .entry(name)
        .or_insert(("gauge", Samples::new()))
        .1
        .insert(key(labels), value);
}

pub fn add(name: &'static str, labels: &[(&str, &str)], value: f64) {
    let mut registry = registry().lock().unwrap();
    let samples = &mut registry
        .families
        .entry(name)
        .or_insert(("counter", Samples::new()))
        .1;
    *samples.entry(key(labels)).or_default() += value;
}

pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

pub fn operation(kind: &'static str, operation: &str, reason: &str, seconds: f64) {
    let result = if reason == "none" {
        "success"
    } else {
        "failure"
    };
    let labels = [
        ("operation", operation),
        ("result", result),
        ("reason", reason),
    ];
    let (count, sum, failures) = match kind {
        "ssh" => (
            "tunnellb_ssh_operations_total",
            "tunnellb_ssh_duration_seconds_sum",
            "tunnellb_ssh_failures_total",
        ),
        _ => (
            "tunnellb_reconciliations_total",
            "tunnellb_reconcile_duration_seconds_sum",
            "tunnellb_reconcile_failures_total",
        ),
    };
    add(count, &labels, 1.0);
    add(sum, &labels, seconds);

    if result == "failure" {
        add(failures, &labels, 1.0);
    }
}

/// Deduplicate repeated polling of immutable completed Jobs, without exporting
/// their identities. Memory is bounded; counters reset with the controller.
pub fn first_completion(uid: &str) -> bool {
    let mut registry = registry().lock().unwrap();

    if registry.completed.iter().any(|seen| seen == uid) {
        return false;
    }

    if registry.completed.len() == 4096 {
        registry.completed.pop_front();
    }

    registry.completed.push_back(uid.into());

    true
}

pub fn retain_enrollments(servers: &[String]) {
    let live: std::collections::BTreeSet<_> = servers
        .iter()
        .map(|server| key(&[("server", server)]))
        .collect();
    let mut registry = registry().lock().unwrap();

    if let Some((_, samples)) = registry
        .families
        .get_mut("tunnellb_last_enrollment_success_timestamp_seconds")
    {
        samples.retain(|labels, _| live.contains(labels));
    }
}

/// Build inventory off-lock, then replace all supplied families in one commit.
#[derive(Default)]
pub struct Snapshot {
    families: BTreeMap<&'static str, Samples>,
}

impl Snapshot {
    pub fn clear(&mut self, name: &'static str) {
        self.families.entry(name).or_default();
    }

    pub fn set(&mut self, name: &'static str, labels: &[(&str, &str)], value: f64) {
        self.families
            .entry(name)
            .or_default()
            .insert(key(labels), value);
    }

    pub fn publish(self) {
        let mut registry = registry().lock().unwrap();

        for (name, samples) in self.families {
            registry.families.insert(name, ("gauge", samples));
        }
    }
}

pub fn inventory_snapshot() -> Snapshot {
    let mut snapshot = Snapshot::default();

    for name in [
        "tunnellb_server_enrolled",
        "tunnellb_publication_provisioned",
        "tunnellb_publication_info",
    ] {
        snapshot.clear(name);
    }

    snapshot
}

pub fn render() -> String {
    let registry = registry().lock().unwrap();
    let mut output = String::new();

    for (name, (kind, samples)) in &registry.families {
        output.push_str(&format!("# HELP {name} TunnelLB operational telemetry; see README metric contract.\n# TYPE {name} {kind}\n"));

        for (labels, value) in samples {
            output.push_str(&format!("{name}{labels} {value}\n"));
        }
    }

    output
}

/// Bind before returning, so address conflicts fail startup. Requests and writes
/// are bounded in time and size; only the exact GET /metrics route is served.
pub async fn listen(address: SocketAddr) -> Result<tokio::task::JoinHandle<()>> {
    let listener = tokio::net::TcpListener::bind(address).await?;

    Ok(serve(listener))
}

fn serve(listener: tokio::net::TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(16));

        while let Ok((mut socket, _)) = listener.accept().await {
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                continue;
            };
            tokio::spawn(async move {
                let _permit = permit;
                let _ = tokio::time::timeout(Duration::from_secs(3), async {
                    let mut buffer = [0; 4096];
                    let mut size = 0;

                    while !buffer[..size].windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        if size == buffer.len() {
                            return Ok::<_, std::io::Error>(());
                        }

                        let read = socket.read(&mut buffer[size..]).await?;

                        if read == 0 {
                            return Ok(());
                        }

                        size += read;
                    }

                    let line = buffer[..size]
                        .split(|byte| *byte == b'\r')
                        .next()
                        .unwrap_or_default();
                    let (status, body) = if matches!(
                        line,
                        b"GET /metrics HTTP/1.0" | b"GET /metrics HTTP/1.1"
                    ) {
                        ("200 OK", render())
                    } else {
                        ("404 Not Found", String::new())
                    };
                    let response = format!("HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    socket.write_all(response.as_bytes()).await
                }).await;
            });
        }
    })
}

/// Export zero baselines before the first scrape, without recording transitions.
pub fn initialize_registration() {
    set("tunnellb_connector_registered", &[], 0.0);
    add("tunnellb_connector_registration_successes_total", &[], 0.0);
    add("tunnellb_connector_registration_losses_total", &[], 0.0);
}

pub fn registration(registered: bool) {
    set("tunnellb_connector_registered", &[], f64::from(registered));
    let counter = if registered {
        set(
            "tunnellb_last_registration_success_timestamp_seconds",
            &[],
            now(),
        );
        "tunnellb_connector_registration_successes_total"
    } else {
        "tunnellb_connector_registration_losses_total"
    };
    add(counter, &[], 1.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn listener_serves_only_metrics() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = serve(listener);

        for (request, status) in [
            ("GET /metrics HTTP/1.1", "200 OK"),
            ("GET /metrics?secret HTTP/1.1", "404 Not Found"),
            ("GET /api/serverinfo HTTP/1.1", "404 Not Found"),
            ("POST /metrics HTTP/1.1", "404 Not Found"),
        ] {
            let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
            socket
                .write_all(format!("{request}\r\nHost: localhost\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut response = String::new();
            socket.read_to_string(&mut response).await.unwrap();
            assert!(response.starts_with(&format!("HTTP/1.1 {status}\r\n")));
        }

        task.abort();
    }

    #[test]
    fn recovery_and_loss_survive_between_scrapes() {
        initialize_registration();
        let baseline = render();
        assert!(baseline.contains("tunnellb_connector_registered{} 0"));
        assert!(baseline.contains("tunnellb_connector_registration_losses_total{} 0"));
        assert!(baseline.contains("tunnellb_connector_registration_successes_total{} 0"));
        registration(true);
        registration(false);
        registration(true);
        let output = render();
        assert!(output.contains("tunnellb_connector_registration_losses_total{} 1"));
        assert!(output.contains("tunnellb_connector_registration_successes_total{} 2"));
        assert!(output.contains("tunnellb_connector_registered{} 1"));
    }

    #[test]
    fn escaping_preserves_one_sample_and_no_injected_metric() {
        assert_eq!(
            key(&[("server", "a\"\nsecret\\")]),
            "{server=\"a\\\"\\nsecret\\\\\"}"
        );
    }

    #[test]
    fn ssh_authentication_is_allowlisted_and_counted() {
        let error = anyhow::Error::new(crate::provision::Diagnostic::SshAuthentication)
            .context("SECRET_SENTINEL");
        let reason = crate::provision::FailureOutcome::from_error(&error)
            .error
            .reason();
        operation("ssh", "enroll", reason, 0.5);
        let output = render();
        assert!(output.contains("tunnellb_ssh_failures_total{operation=\"enroll\",result=\"failure\",reason=\"SSHAuthenticationFailed\"} "));
        assert!(!output.contains("SECRET_SENTINEL"));
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;

    #[tokio::test]
    async fn fragmented_headers_wait_for_completion() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = serve(listener);
        let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
        socket.write_all(b"GET /met").await.unwrap();
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), socket.read(&mut byte),)
                .await
                .is_err()
        );
        socket
            .write_all(b"rics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        task.abort();
    }

    #[test]
    fn snapshot_publishes_together_and_preserves_unsupplied_families() {
        set("snapshot_a", &[], 1.0);
        set("snapshot_b", &[], 2.0);
        set("snapshot_restarts", &[], 3.0);
        let mut snapshot = Snapshot::default();
        snapshot.set("snapshot_a", &[], 4.0);
        snapshot.clear("snapshot_b");
        assert!(render().contains("snapshot_a{} 1"));
        snapshot.publish();
        let output = render();
        assert!(output.contains("snapshot_a{} 4"));
        assert!(!output.contains("snapshot_b{}"));
        assert!(output.contains("snapshot_restarts{} 3"));
    }
}
