use super::{digest, enroll_script, shell_quote};
use crate::provision::Request;

pub(super) struct TestHost(tempfile::TempDir);

impl TestHost {
    pub(super) fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;

        std::fs::create_dir_all("/tmp/codex").unwrap();
        let directory = tempfile::tempdir_in("/tmp/codex").unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(directory.path().join("systemd")).unwrap();

        Self(directory)
    }

    pub(super) fn path(&self, path: &str) -> std::path::PathBuf {
        self.0.path().join(path)
    }

    pub(super) fn run(&self, script: String) -> std::process::Output {
        use std::os::unix::fs::MetadataExt;

        let root = self.0.path();
        let uid = std::fs::metadata(root).unwrap().uid();
        let mocks = format!(
            r#"
test_root={root}
# System primitives that affect the real host are replaced only in this
# scratch fixture; the production ownership, fencing and cleanup code runs.
chown() {{ :; }}
getent() {{ return 1; }}
useradd() {{ :; }}
ss() {{
    case "$2" in -lntp) protocol=tcp ;; -lnup) protocol=udp ;; *) return 1 ;; esac
    sockets="$test_root/sockets-$protocol-${{3##*:}}"
    if [ -f "$sockets" ]; then cat "$sockets"; fi
}}
sleep() {{ :; }}
install() {{ command cp -- "${{@: -2:1}}" "${{@: -1}}"; }}
sha256sum() {{
    if [ "$1" = "$binary" ]; then
        case "$(uname -m)" in x86_64) checksum=$amd64_digest ;; *) checksum=$arm64_digest ;; esac
        printf '%s  %s\n' "$checksum" "$binary"
    else command sha256sum "$@"; fi
}}
systemctl() {{
    printf '%s\n' "$*" >> "$test_root/commands"
    case "$1" in
        show)
            case "$3" in
                --property=FragmentPath) printf '%s\n' "$unitfile" ;;
                --property=MainPID) if [ -f "$test_root/active" ]; then printf '123\n'; else printf '0\n'; fi ;;
                --property=DropInPaths) printf '\n' ;;
                *) return 1 ;;
            esac ;;
        is-active) [ -f "$test_root/active" ] ;;
        restart)
            [ ! -f "$test_root/fail-start" ] || return 1
            printf '%s\n' "$unit" > "$test_root/active" ;;
        disable)
            [ ! -f "$test_root/fail-stop" ] || return 1
            command rm -f "$test_root/active" ;;
        list-units) if [ -f "$test_root/active" ]; then cat "$test_root/active"; fi ;;
        enable|reset-failed|daemon-reload) : ;;
        *) return 1 ;;
    esac
}}
rm() {{
    target=${{@: -1}}
    if [ "$target" = "${{pub:-}}" ] && [ -f "$test_root/fail-payload-delete" ]; then
        command rm -f "$target/owner" "$test_root/fail-payload-delete"
        return 1
    fi
    if [ "$target" = "$owned" ] && [ -f "$test_root/fail-owned-delete" ]; then
        command rm -f "$target/owner" "$test_root/fail-owned-delete"
        return 1
    fi
    command rm "$@"
}}
"#,
            root = shell_quote(root.to_str().unwrap())
        );
        let mapped = script
            .replace("/var/lib/tunnellb", self.path("state").to_str().unwrap())
            .replace("/opt/tunnellb", self.path("opt").to_str().unwrap())
            .replace(
                "/etc/systemd/system",
                self.path("systemd").to_str().unwrap(),
            )
            .replace("/run/tunnellb", self.path("lock").to_str().unwrap())
            .replace(
                "$(stat -c %u \"$1\")\" = 0",
                &format!("$(stat -c %u \"$1\")\" = {uid}"),
            )
            .replacen("\nlock\n", &format!("\n{mocks}\nlock\n"), 1);

        std::process::Command::new("bash")
            .args(["-c", &mapped])
            .output()
            .unwrap()
    }

    pub(super) fn success(&self, script: String) {
        let output = self.run(script);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("TUNNELLB_OK"));
    }

    pub(super) fn failure(&self, script: String, code: &str) {
        let output = self.run(script);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .any(|line| line == format!("TUNNELLB_ERROR {code}")),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    pub(super) fn enroll(&self, request: &Request) {
        let binary = b"#!/bin/sh\nexit 0\n";
        self.success(enroll_script(request, Some(binary), &digest(binary)).unwrap());
    }

    pub(super) fn flag(&self, flag: &str) {
        std::fs::write(self.path(flag), "fail once").unwrap();
    }
}
