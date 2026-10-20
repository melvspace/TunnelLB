use std::{io::Write, process::Stdio};

use super::*;
use crate::provision::{Operation, binary::AMD64_SHA256, test_support::request};

mod host;
mod lifecycle;
use host::TestHost;

#[test]
fn shell_quote_is_literal_even_for_shell_metacharacters() {
    let value = "' ; $(printf bad) `printf bad` \n\" * \\";
    let output = std::process::Command::new("bash")
        .args(["-c", &format!("printf '%s' {}", shell_quote(value))])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, value.as_bytes());
}

#[test]
fn generated_scripts_are_valid_bash_and_secrets_are_encoded() {
    let request = request(Operation::Apply);
    let scripts = [
        probe_script(&request),
        enroll_script(&request, Some(b"fake binary"), AMD64_SHA256).unwrap(),
        enroll_script(&request, None, AMD64_SHA256).unwrap(),
        apply_script(&request).unwrap(),
        remove_script(&request).unwrap(),
        uninstall_script(&request).unwrap(),
    ];

    for script in scripts {
        let mut child = std::process::Command::new("bash")
            .arg("-n")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!script.contains(request.server_private_key.as_deref().unwrap()));
    }
}

#[test]
fn port_conflicts_reject_other_processes_and_accept_only_owned_listeners() {
    let request = request(Operation::Apply);
    let host = TestHost::new();
    host.enroll(&request);
    host.success(apply_script(&request).unwrap());

    for endpoint in ["tcp-22000", "tcp-443", "udp-53"] {
        for (sockets, permitted) in [
            ("", true),
            (
                "LISTEN 0 100 0.0.0.0:443 *:* users:((\"frps\",pid=123,fd=3))",
                true,
            ),
            (
                "LISTEN 0 100 0.0.0.0:443 *:* users:((\"frps\",pid=456,fd=3))",
                false,
            ),
            (
                "LISTEN 0 100 0.0.0.0:443 *:* users:((\"frps\",pid=123,fd=3),(\"other\",pid=456,fd=4))",
                false,
            ),
            ("LISTEN 0 100 0.0.0.0:443 *:*", false),
        ] {
            std::fs::write(host.path(&format!("sockets-{endpoint}")), sockets).unwrap();

            if permitted {
                host.success(apply_script(&request).unwrap());
            } else {
                host.failure(apply_script(&request).unwrap(), "occupied-port");
            }
        }

        std::fs::remove_file(host.path(&format!("sockets-{endpoint}"))).unwrap();
    }
}
