use super::{digest, enroll_script, reserve_script, shell_quote};
use crate::provision::{
    AllocationOutcome, Request,
    binary::{AMD64_SHA256, ARM64_SHA256},
};

const BINARY: &[u8] = b"#!/bin/sh\nexit 0\n";

pub(super) struct TestHost(tempfile::TempDir);

impl TestHost {
    pub(super) fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;

        std::fs::create_dir_all("/tmp/codex").unwrap();
        let directory = tempfile::tempdir_in("/tmp/codex").unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(directory.path().join("systemd")).unwrap();
        std::fs::create_dir(directory.path().join("active")).unwrap();
        std::fs::create_dir(directory.path().join("ufw-apps")).unwrap();
        std::fs::create_dir(directory.path().join("ufw-rules")).unwrap();
        std::fs::set_permissions(
            directory.path().join("ufw-apps"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::write(directory.path().join("user.rules"), "").unwrap();
        std::fs::set_permissions(
            directory.path().join("user.rules"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

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
command() {{
    if [ "$*" = "-v ufw" ] && [ -f "$test_root/no-ufw" ]; then return 1; fi
    builtin command "$@"
}}
ufw() {{
    printf '%s\n' "$*" >> "$test_root/firewall-commands"
    case "$*" in
        status)
            [ ! -f "$test_root/fail-firewall-inspection" ] || return 1
            if [ -f "$test_root/inactive-ufw" ]; then printf 'Status: inactive\n'; else printf 'Status: active\n'; fi ;;
        "show added")
            for rule in "$test_root/ufw-rules/"*; do
                [ -f "$rule" ] && cat "$rule"
            done
            return 0 ;;
        "allow in from 0.0.0.0/0 to any app "*)
            [ ! -f "$test_root/fail-firewall-open" ] || return 1
            local profile=${{8}} tag=${{10}}
            [ "${{#profile}}" -le 64 ] || return 1
            [ -f "$test_root/ufw-apps/$profile" ] || return 1
            printf "ufw allow %s comment '%s'\n" "$profile" "$tag" > "$test_root/ufw-rules/$profile" ;;
        "--force delete allow in from 0.0.0.0/0 to any app "*)
            [ ! -f "$test_root/fail-firewall-close" ] || return 1
            local profile=${{10}}
            command rm -f "$test_root/ufw-rules/$profile" ;;
        *) return 1 ;;
    esac
}}
ss() {{
    printf '%s\n' "$*" >> "$test_root/socket-probes"
    if [ "$2" = -lntu ]; then
        if [ -f "$test_root/sockets-snapshot" ]; then cat "$test_root/sockets-snapshot"; return; fi
        for socket in "$test_root"/sockets-tcp-* "$test_root"/sockets-udp-*; do
            [ -s "$socket" ] || continue
            endpoint=${{socket##*/sockets-}}
            protocol=${{endpoint%-*}}
            if [ "$protocol" = tcp ]; then state=LISTEN; else state=UNCONN; fi
            printf '%s %s 0 0 0.0.0.0:%s *:*\n' "$protocol" "$state" "${{endpoint##*-}}"
        done
        return 0
    fi
    case "$2" in -lntp) protocol=tcp ;; -lnup) protocol=udp ;; *) return 1 ;; esac
    sockets="$test_root/sockets-$protocol-${{3##*:}}"
    if [ -f "$sockets" ]; then cat "$sockets"; fi
}}
sleep() {{ :; }}
sync() {{
    printf 'sync %s\n' "$*" >> "$test_root/durability"
    if [[ "$1" == *.claim ]] && [ -f "$test_root/fail-claim-sync" ]; then
        command rm -f "$test_root/fail-claim-sync"
        return 1
    fi
    if [ "$1" = "$retired" ] && [ -f "$test_root/fail-retired-sync" ]; then return 1; fi
    if [ -f "$test_root/fail-directory-sync" ] && [ "$1" = "$(cat "$test_root/fail-directory-sync")" ]; then return 1; fi
    if [ -f "$test_root/fail-firewall-profile-sync" ] && [ "$1" = "$test_root/ufw-apps" ] && [ ! -f "${{firewall_file:-}}" ]; then return 1; fi
}}
install() {{ command cp -- "${{@: -2:1}}" "${{@: -1}}"; chmod 0755 "${{@: -1}}"; }}
systemctl() {{
    printf '%s\n' "$*" >> "$test_root/commands"
    local active="$test_root/active/${{unit:-unused}}"
    case "$1" in
        show)
            case "$3" in
                --property=FragmentPath) printf '%s\n' "$unitfile" ;;
                --property=MainPID) if [ -f "$active" ]; then cat "$active"; else printf '0\n'; fi ;;
                --property=DropInPaths) printf '\n' ;;
                *) return 1 ;;
            esac ;;
        is-active) [ -f "$active" ] ;;
        restart)
            [ ! -f "$test_root/fail-start" ] || return 1
            if [ ! -f "$test_root/no-ufw" ]; then
                local firewall_profile="$test_root/ufw-rules/TunnelLB-$(printf '%s' "$owner:$publication" | sha256sum | cut -c1-32)"
                [ -f "$firewall_profile" ] || return 1
            fi
            printf '%s\n' "$BASHPID" > "$active" ;;
        disable)
            [ ! -f "$test_root/fail-stop" ] || return 1
            command rm -f "$active" ;;
        list-units)
            for active in "$test_root/active/"*; do
                if [[ "${{active##*/}}" == ${{@: -1}} ]]; then printf '%s\n' "${{active##*/}}"; fi
            done ;;
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
    if [ "$target" = "$generations/${{publication:-}}" ] && [ -f "$test_root/fail-generation-delete" ]; then
        command rm -f "$test_root/fail-generation-delete"
        return 1
    fi
    command rm "$@"
}}
"#,
            root = shell_quote(root.to_str().unwrap())
        );
        let mapped = script
            .replace(AMD64_SHA256, &digest(BINARY))
            .replace(ARM64_SHA256, &digest(BINARY))
            .replace("/var/lib/tunnellb", self.path("state").to_str().unwrap())
            .replace("/opt/tunnellb", self.path("opt").to_str().unwrap())
            .replace(
                "/etc/systemd/system",
                self.path("systemd").to_str().unwrap(),
            )
            .replace("/run/tunnellb", self.path("lock").to_str().unwrap())
            .replace(
                "/etc/ufw/applications.d",
                self.path("ufw-apps").to_str().unwrap(),
            )
            .replace("/etc/ufw", root.to_str().unwrap())
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
        self.success(enroll_script(request, Some(BINARY), &digest(BINARY)).unwrap());
    }

    pub(super) fn reserve(&self, request: &Request) -> AllocationOutcome {
        let output = self.run(reserve_script(request).unwrap());
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        crate::provision::scripts::parse_allocation(&String::from_utf8_lossy(&output.stdout))
            .unwrap()
    }

    pub(super) fn active(&self, request: &Request) -> std::path::PathBuf {
        self.path(&format!(
            "active/tunnellb-{}@{}.service",
            request.server_uid,
            request.publication.as_ref().unwrap().id
        ))
    }

    pub(super) fn flag(&self, flag: &str) {
        std::fs::write(self.path(flag), "fail once").unwrap();
    }
}
