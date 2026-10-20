//! Host eligibility, installation, and terminal machine teardown.
use anyhow::Result;

use super::{
    host::{prelude, systemd_unit},
    shell_quote, upload,
};

use crate::provision::{Operation, Request};

pub(in crate::provision) fn probe_script(request: &Request) -> String {
    let mut script = prelude(request);
    script.push_str(r#"
[ "$(id -u)" = 0 ] || fail sudo
[ -r /etc/os-release ] || fail platform
. /etc/os-release
case "$ID" in debian|ubuntu) ;; *) fail platform ;; esac
[ -d /run/systemd/system ] && [ "$(cat /proc/1/comm)" = systemd ] || fail platform
for program in systemctl ss flock sha256sum base64 install stat timeout sync; do command -v "$program" >/dev/null || fail prerequisites; done
case "$(uname -m)" in x86_64) architecture=amd64 ;; aarch64|arm64) architecture=arm64 ;; *) fail architecture ;; esac
printf 'TUNNELLB_ARCH %s\n' "$architecture"
"#);

    if matches!(request.operation, Operation::Enroll | Operation::Apply) {
        script.push_str(
            r#"
# Older systemd versions silently ignore newer sandbox directives.
systemd_version=$(systemctl --version | awk 'NR == 1 { print $2 }')
case "$systemd_version" in ''|*[!0-9]*) fail platform-version ;; esac
[ "$systemd_version" -ge 244 ] || fail platform-version
"#,
        );
    }

    if request.operation == Operation::Enroll {
        script.push_str(
            r#"
# This is an advisory eligibility check, not proof about an untrusted host.
for program in k3s tailscale tailscaled; do
    if command -v "$program" >/dev/null 2>&1; then fail dedicated-host; fi
done
for path in /etc/rancher/k3s /var/lib/rancher/k3s /var/lib/tailscale; do
    if [ -e "$path" ]; then fail dedicated-host; fi
done
for name in k3s.service k3s-agent.service tailscaled.service; do
    if systemctl cat "$name" >/dev/null 2>&1; then fail dedicated-host; fi
done
if [ -e "$binbase" ] || [ -L "$binbase" ]; then
    check_binary_owner
    if [ -e "$binary" ] || [ -L "$binary" ]; then
        plain_file "$binary"
        printf 'TUNNELLB_BINARY %s\n' "$(sha256sum "$binary" | cut -d' ' -f1)"
    fi
fi
"#,
        );
    }

    script.push_str("printf 'TUNNELLB_OK\\n'\n");

    script
}

pub(in crate::provision) fn enroll_script(
    request: &Request,
    binary: Option<&[u8]>,
    expected_digest: &str,
) -> Result<String> {
    let mut script = prelude(request);
    script.push_str(r#"
lock
claim_directory "$base"
check_not_uninstalled
claim_directory "$owned"
claim_directory "$binbase"
chmod 0755 "$base" "$owned" "$binbase"
if getent passwd "$account" >/dev/null; then
    [ "$(getent passwd "$account" | cut -d: -f5)" = "TunnelLB-$owner" ] && [ "$(id -u "$account")" != 0 ] || fail account-owner
    [ "$(getent passwd "$account" | cut -d: -f7)" = /usr/sbin/nologin ] || fail account-owner
    [ "$(id -gn "$account")" = "$account" ] && [ "$(id -G "$account")" = "$(id -g "$account")" ] || fail account-owner
else
    if getent group "$account" >/dev/null; then fail account-owner; fi
    useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --comment "TunnelLB-$owner" "$account"
fi
if [ -e "$owned/publications" ] || [ -L "$owned/publications" ]; then plain_dir "$owned/publications"; else mkdir -m 0755 "$owned/publications"; fi
if [ -e "$(dirname "$binary")" ] || [ -L "$(dirname "$binary")" ]; then plain_dir "$(dirname "$binary")"; else mkdir -m 0755 "$(dirname "$binary")"; fi
chmod 0755 "$owned/publications" "$(dirname "$binary")"
stage=$(mktemp -d "$owned/.enroll.XXXXXXXX")
trap 'rm -rf --one-file-system -- "$stage"' EXIT
"#);
    script.push_str(&format!(
        "expected_digest={}\n",
        shell_quote(expected_digest)
    ));

    if let Some(binary) = binary {
        upload(&mut script, "\"$stage/frps\"", binary);
        script.push_str(
            r#"
[ "$(sha256sum "$stage/frps" | cut -d' ' -f1)" = "$expected_digest" ] || fail checksum
if [ -e "$binary" ] || [ -L "$binary" ]; then plain_file "$binary"; fi
if [ ! -f "$binary" ] || [ "$(sha256sum "$binary" | cut -d' ' -f1)" != "$expected_digest" ]; then
    install -o root -g root -m 0755 "$stage/frps" "$(dirname "$binary")/.frps.new"
    mv -fT "$(dirname "$binary")/.frps.new" "$binary"
fi
"#,
        );
    } else {
        script.push_str("plain_file \"$binary\"\n[ \"$(sha256sum \"$binary\" | cut -d' ' -f1)\" = \"$expected_digest\" ] || fail checksum\n");
    }

    script.push_str("chown root:root \"$binary\"\nchmod 0755 \"$binary\"\n");

    upload(
        &mut script,
        "\"$stage/unit\"",
        systemd_unit(&request.machine_uid).as_bytes(),
    );
    script.push_str(
        r#"
if [ -e "$unitfile" ] || [ -L "$unitfile" ]; then
    if [ -e "$owned/unit.sha256" ] || [ -L "$owned/unit.sha256" ]; then check_template; else
        plain_file "$unitfile"; cmp -s "$stage/unit" "$unitfile" || fail unit-owner
    fi
fi
if [ ! -f "$unitfile" ] || ! cmp -s "$stage/unit" "$unitfile"; then
    install -o root -g root -m 0644 "$stage/unit" "$unitfile.new"
    mv -fT "$unitfile.new" "$unitfile"
    systemctl daemon-reload
fi
sha256sum "$unitfile" | cut -d' ' -f1 > "$owned/unit.sha256.new"
mv -fT "$owned/unit.sha256.new" "$owned/unit.sha256"
printf 'TUNNELLB_OK\n'
"#,
    );

    Ok(script)
}

pub(in crate::provision) fn uninstall_script(request: &Request) -> Result<String> {
    let mut script = prelude(request);
    script.push_str(
        r#"
lock
claim_directory "$base"
if [ -e "$base/uninstalled" ] || [ -L "$base/uninstalled" ]; then
    marker "$base/uninstalled" "$owner"
else
    if [ -e "$owned" ] || [ -L "$owned" ]; then check_owner; fi
    # Persist terminal intent even on an empty host. A delayed first Enroll
    # must not install anything after this Uninstall has completed.
    persist_marker "$base/uninstalled" "$owner"
fi
if [ -e "$owned" ] || [ -L "$owned" ]; then check_cleanup_owner; fi
if [ -e "$owned/publications" ] || [ -L "$owned/publications" ]; then
    plain_dir "$owned/publications"
    for pub in "$owned/publications/"*; do
        if [ ! -e "$pub" ] && [ ! -L "$pub" ]; then continue; fi
        publication=${pub##*/}
        case "$publication" in ''|*[!a-zA-Z0-9_-]*) fail owner ;; esac
        unit="tunnellb-$owner@$publication.service"
        cleanup_publication
    done
fi
if [ -e "$unitfile" ] || [ -L "$unitfile" ]; then
    check_template
    # An administrator may have removed a publication directory while its
    # process still ran. Stop every remaining owned template instance as well.
    instances=$(systemctl list-units --all --plain --no-legend --no-pager "tunnellb-$owner@*.service")
    while read -r unit rest; do
        [ -n "$unit" ] || continue
        case "$unit" in "tunnellb-$owner@"*.service) ;; *) fail unit-owner ;; esac
        publication=${unit#"tunnellb-$owner@"}
        publication=${publication%.service}
        case "$publication" in ''|*[!a-zA-Z0-9_-]*) fail unit-owner ;; esac
        pub="$owned/publications/$publication"
        cleanup_publication
    done <<< "$instances"
    rm -f -- "$unitfile"
    systemctl daemon-reload
fi
if [ -e "$binbase" ] || [ -L "$binbase" ]; then
    check_binary_owner
    if [ -e "$binary" ] || [ -L "$binary" ]; then plain_file "$binary"; rm -f -- "$binary"; fi
    rmdir -- "$(dirname "$binary")" 2>/dev/null || true
    # Retain the global marker even when only an empty installation remains.
    # Removing the marker before its directory would make a crash unrecoverable.
fi
# The dedicated, locked system account is deliberately retained: an admin may
# have granted it other resources. It has no authorized key or login shell.
rm -rf --one-file-system -- "$owned"
# Keep the immutable global ownership tombstone. It both prevents another
# Machine from taking over the host and makes interrupted teardown retryable.
printf 'TUNNELLB_OK\n'
"#,
    );

    Ok(script)
}
