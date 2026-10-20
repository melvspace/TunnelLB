//! Shared remote ownership, durability, and systemd sandbox contracts.
use super::{digest, shell_quote};
use crate::{
    provision::{
        Request,
        binary::{AMD64_SHA256, ARM64_SHA256},
    },
    transport::FRP_VERSION,
};

fn service_user(uid: &str) -> String {
    format!("tlb-{}", &digest(uid.as_bytes())[..20])
}

pub(super) fn prelude(request: &Request) -> String {
    format!(
        r#"set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077
owner={owner}
base=/var/lib/tunnellb
owned="$base/$owner"
revocations="$owned/revocations"
generations="$owned/generations"
claims="$base/claims"
retired="$base/retired/$owner"
binbase=/opt/tunnellb
binary="$binbase/{version}/frps"
amd64_digest={amd64_digest}
arm64_digest={arm64_digest}
account={account}
template="tunnellb-$owner@.service"
unitfile="/etc/systemd/system/$template"
unit_digest={unit_digest}
fail() {{ printf 'TUNNELLB_ERROR %s\n' "$1" >&2; exit 1; }}
trap 'fail command' ERR
safe_mode() {{ mode=$(stat -c %a "$1"); [ "$((8#$mode & 022))" = 0 ] || fail unsafe-path; }}
plain_dir() {{ [ ! -L "$1" ] && [ -d "$1" ] && [ "$(stat -c %u "$1")" = 0 ] || fail unsafe-path; safe_mode "$1"; }}
plain_file() {{ [ ! -L "$1" ] && [ -f "$1" ] && [ "$(stat -c %u "$1")" = 0 ] || fail unsafe-path; safe_mode "$1"; }}
marker() {{ plain_file "$1"; [ "$(cat "$1")" = "$2" ] || fail owner; }}
claim_directory() {{
    if [ -e "$1" ] || [ -L "$1" ]; then
        plain_dir "$1"; marker "$1/owner" "$owner"
    else
        plain_dir "$(dirname "$1")"
        claim=$(mktemp -d "$(dirname "$1")/.claim.XXXXXXXX")
        printf '%s\n' "$owner" > "$claim/owner"
        chmod 0755 "$claim"
        sync "$claim/owner" "$claim"
        mv -T -- "$claim" "$1"
    fi
    sync "$1/owner" "$1" "$(dirname "$1")"
}}
persist_marker() {{
    if [ -e "$1" ] || [ -L "$1" ]; then
        marker "$1" "$2"
    else
        plain_dir "$(dirname "$1")"
        pending_marker=$(mktemp "$1.pending.XXXXXXXX")
        printf '%s\n' "$2" > "$pending_marker"
        sync "$pending_marker"
        mv -T -- "$pending_marker" "$1"
    fi
    sync "$1" "$(dirname "$1")"
}}
lock() {{
    reject_legacy
    if [ ! -e /run/tunnellb ] && [ ! -L /run/tunnellb ]; then
        mkdir -m 0700 /run/tunnellb 2>/dev/null || [ -d /run/tunnellb ] || fail unsafe-path
    fi
    plain_dir /run/tunnellb
    [ ! -L /run/tunnellb/provision.lock ] || fail unsafe-path
    if [ -e /run/tunnellb/provision.lock ]; then plain_file /run/tunnellb/provision.lock; fi
    exec 9>/run/tunnellb/provision.lock
    flock -w 15 9 || fail busy
    reject_legacy
}}
reject_legacy() {{
    for legacy in "$base/owner" "$binbase/owner"; do
        [ ! -e "$legacy" ] && [ ! -L "$legacy" ] || fail legacy-layout
    done
}}
shared_directory() {{
    if [ -e "$1" ] || [ -L "$1" ]; then
        plain_dir "$1"; marker "$1/schema" tunnellb-shared-v1
    else
        plain_dir "$(dirname "$1")"
        shared_stage=$(mktemp -d "$1.pending.XXXXXXXX")
        printf 'tunnellb-shared-v1\n' > "$shared_stage/schema"
        chmod 0755 "$shared_stage"
        sync "$shared_stage/schema" "$shared_stage"
        mv -T -- "$shared_stage" "$1"
    fi
    sync "$1/schema" "$1" "$(dirname "$1")"
}}
ensure_directory() {{
    if [ ! -e "$1" ] && [ ! -L "$1" ]; then mkdir -m 0700 "$1"; fi
    plain_dir "$1"
}}
initialize_host() {{
    shared_directory "$base"
    ensure_directory "$claims"
    ensure_directory "$base/retired"
    sync "$base"
}}
check_global_owner() {{
    reject_legacy
    plain_dir "$base"; marker "$base/schema" tunnellb-shared-v1
}}
check_not_uninstalled() {{
    plain_dir "$base/retired"
    if [ -e "$retired" ] || [ -L "$retired" ]; then
        marker "$retired" "$owner"
        fail machine-revoked
    fi
}}
check_owner() {{
    check_global_owner
    plain_dir "$owned"; marker "$owned/owner" "$owner"
}}
check_cleanup_owner() {{
    check_global_owner; plain_dir "$owned"
    if [ -e "$owned/owner" ] || [ -L "$owned/owner" ]; then
        marker "$owned/owner" "$owner"
    else
        # An interrupted recursive uninstall may already have removed the
        # inner owner file. Its durable terminal intent remains authoritative.
        marker "$retired" "$owner"
    fi
}}
check_binary_owner() {{
    plain_dir "$binbase"; marker "$binbase/schema" tunnellb-shared-v1
    plain_dir "$(dirname "$binary")"
}}
check_template() {{
    plain_file "$unitfile"
    expected_unit_digest=$unit_digest
    if [ -e "$owned/unit.sha256" ] || [ -L "$owned/unit.sha256" ]; then
        plain_file "$owned/unit.sha256"
        expected_unit_digest=$(cat "$owned/unit.sha256")
    fi
    [ "$(sha256sum "$unitfile" | cut -d' ' -f1)" = "$expected_unit_digest" ] || fail unit-owner
    [ ! -e "/etc/systemd/system/$template.d" ] || fail unit-owner
}}
check_unit() {{
    check_template
    [ ! -e "/etc/systemd/system/$unit" ] && [ ! -L "/etc/systemd/system/$unit" ] || fail unit-owner
    [ ! -e "/etc/systemd/system/$unit.d" ] || fail unit-owner
    fragment=$(systemctl show "$unit" --property=FragmentPath --value)
    [ "$fragment" = "$unitfile" ] || fail unit-owner
    [ -z "$(systemctl show "$unit" --property=DropInPaths --value)" ] || fail unit-owner
}}
valid_generation() {{
    case "$1" in ''|*[!0-9a-f]*) fail generation-state ;; esac
    [ "${{#1}}" -eq 64 ] || fail generation-state
}}
read_generation_record() {{
    plain_file "$1"
    generation_record=$(cat "$1")
    current_generation=${{generation_record%%:*}}
    current_configuration_hash=${{generation_record#*:}}
    [ "$current_generation" != "$generation_record" ] || fail generation-state
    valid_generation "$current_generation"; valid_generation "$current_configuration_hash"
}}
check_publication() {{
    plain_dir "$pub"
    if [ -e "$pub/owner" ] || [ -L "$pub/owner" ]; then
        marker "$pub/owner" "$owner:$publication"
    elif [ -e "$retired" ] || [ -L "$retired" ]; then
        marker "$retired" "$owner"
    else
        # The reservation outlives the payload, including partial rm -rf.
        read_claim "$claims/$owner/$publication.claim"
    fi
}}
read_current_generation() {{
    current_generation=
    current_configuration_hash=
    if [ -e "$generations" ] || [ -L "$generations" ]; then
        plain_dir "$generations"; marker "$generations/owner" "$owner"
        if [ -e "$generations/$publication" ] || [ -L "$generations/$publication" ]; then
            read_generation_record "$generations/$publication"
            return
        fi
    fi
}}
check_generation_not_revoked() {{
    if [ -e "$revocations" ] || [ -L "$revocations" ]; then
        plain_dir "$revocations"; marker "$revocations/owner" "$owner"
        if [ -e "$revocations/$publication-$generation" ] || [ -L "$revocations/$publication-$generation" ]; then
            marker "$revocations/$publication-$generation" "$owner:$publication:$generation"
            fail generation-revoked
        fi
    fi
}}
cleanup_publication() {{
    if [ -e "$pub" ] || [ -L "$pub" ]; then
        check_publication
    fi
    if [ -e "$unitfile" ] || [ -L "$unitfile" ]; then
        check_unit
        systemctl disable --now "$unit" >/dev/null 2>&1 || fail stop
        if systemctl is-active --quiet "$unit"; then fail stop; fi
        systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    elif [ -e "$pub" ]; then
        fail unit-owner
    else
        # A missing template/payload does not prove its loaded unit stopped.
        [ "$(systemctl show "$unit" --property=MainPID --value)" = 0 ] || fail unit-owner
    fi
    if [ -e "$pub" ]; then
        rm -rf --one-file-system -- "$pub"
    fi
    if [ -e "$owned/publications" ] || [ -L "$owned/publications" ]; then
        plain_dir "$owned/publications"
        sync "$owned/publications"
    fi
}}
"#,
        owner = shell_quote(&request.machine_uid),
        account = shell_quote(&service_user(&request.machine_uid)),
        version = FRP_VERSION,
        amd64_digest = AMD64_SHA256,
        arm64_digest = ARM64_SHA256,
        unit_digest = digest(systemd_unit(&request.machine_uid).as_bytes())
    ) + super::reservation::CLAIM_FUNCTIONS
}

pub(super) fn systemd_unit(uid: &str) -> String {
    format!(
        r#"# Owned by TunnelLB Machine {uid}
[Unit]
Description=TunnelLB publication %i for Machine {uid}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User={account}
Group={account}
ExecStart=/opt/tunnellb/{version}/frps -c /var/lib/tunnellb/{uid}/publications/%i/frps.toml
Restart=on-failure
RestartSec=3
TimeoutStopSec=15
KillMode=control-group
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
UMask=0077
# Each instance sees only its own credentials within the owned state tree.
TemporaryFileSystem=/var/lib/tunnellb:ro
BindReadOnlyPaths=/var/lib/tunnellb/{uid}/publications/%i
ReadOnlyPaths=/opt/tunnellb/{version}/frps
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"#,
        account = service_user(uid),
        version = FRP_VERSION
    )
}
