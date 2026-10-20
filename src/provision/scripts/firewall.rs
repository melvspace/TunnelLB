//! UFW profiles give publication rules a distinct identity from administrator rules.
use std::collections::BTreeSet;

use crate::api::Publication;

pub(super) fn ports(publication: &Publication) -> String {
    let mut ports = publication
        .service
        .ports
        .iter()
        .map(|port| format!("{}/{}", port.port, port.protocol.as_str().to_lowercase()))
        .collect::<BTreeSet<_>>();
    ports.insert(format!("{}/tcp", publication.control_port));

    ports.into_iter().collect::<Vec<_>>().join("|")
}

pub(super) const FUNCTIONS: &str = r#"
inspect_firewall() {
    firewall_available=no
    if command -v ufw >/dev/null 2>&1; then
        local status
        status=$(ufw status 2>/dev/null) || fail firewall-inspection
        case "$status" in
            "Status: active"*) ;;
            "Status: inactive") ;;
            *) fail firewall-inspection ;;
        esac
        [ -d /etc/ufw/applications.d ] || fail firewall-inspection
        plain_dir /etc/ufw/applications.d
        firewall_available=yes
    fi
}
firewall_paths() {
    firewall_directory="$owned/firewall"
    firewall_intent="$firewall_directory/$publication"
    firewall_tag="tunnellb:$owner:$publication"
    # UFW profile names are limited to 64 characters. A 128-bit digest leaves
    # room for the prefix and is always checked against the full owner marker.
    firewall_name="TunnelLB-$(printf '%s' "$owner:$publication" | sha256sum | cut -c1-32)"
    firewall_file="/etc/ufw/applications.d/$firewall_name"
}
install_firewall_profile() {
    plain_dir /etc/ufw/applications.d
    plain_file "$firewall_intent"
    if [ -e "$firewall_file" ] || [ -L "$firewall_file" ]; then
        plain_file "$firewall_file"
        cmp -s "$firewall_intent" "$firewall_file" || fail firewall-configuration
    else
        local pending
        pending=$(mktemp "/etc/ufw/applications.d/.$firewall_name.XXXXXXXX")
        install -o root -g root -m 0644 "$firewall_intent" "$pending"
        sync "$pending"
        mv -T -- "$pending" "$firewall_file"
    fi
    sync "$firewall_file" /etc/ufw/applications.d
}
sync_firewall_rules() {
    # UFW persists its IPv4 rules here. Commit rule deletion before releasing
    # a claim, so a power loss cannot resurrect an allow for a reused port.
    plain_file /etc/ufw/user.rules
    sync /etc/ufw/user.rules /etc/ufw
}
open_firewall() {
    firewall_paths
    inspect_firewall
    if [ "$firewall_available" = no ]; then
        [ ! -e "$firewall_intent" ] && [ ! -L "$firewall_intent" ] || fail firewall-unavailable
        return
    fi
    claim_directory "$firewall_directory"
    local firewall_profile
    firewall_profile=$(printf '# TunnelLB %s:%s\n[%s]\ntitle=TunnelLB publication\ndescription=Managed by TunnelLB\nports=%s' "$owner" "$publication" "$firewall_name" "$firewall_ports")
    # Persist the entire immutable profile before creating any UFW resource.
    # It survives payload deletion and makes interrupted Apply/Remove retryable.
    persist_marker "$firewall_intent" "$firewall_profile"
    install_firewall_profile
    local rules
    rules=$(ufw show added 2>/dev/null) || fail firewall-inspection
    # The application name distinguishes our rules from administrator port
    # rules. Refuse changes to other rules using our profile. Append keeps
    # administrator deny/limit rules ahead of this allow. Explicit IPv4 avoids
    # opening an unrelated IPv6 endpoint.
    if printf '%s\n' "$rules" | grep -F -- "$firewall_name" | grep -Fvx -- "ufw allow $firewall_name comment '$firewall_tag'" >/dev/null; then fail firewall-configuration; fi
    ufw allow in from 0.0.0.0/0 to any app "$firewall_name" comment "$firewall_tag" >/dev/null 2>&1 || fail firewall-configuration
    rules=$(ufw show added 2>/dev/null) || fail firewall-inspection
    printf '%s\n' "$rules" | grep -Fx -- "ufw allow $firewall_name comment '$firewall_tag'" >/dev/null || fail firewall-configuration
    sync_firewall_rules
}
close_firewall() {
    firewall_paths
    if [ ! -e "$firewall_intent" ] && [ ! -L "$firewall_intent" ]; then
        [ ! -e "$firewall_file" ] && [ ! -L "$firewall_file" ] || fail firewall-cleanup
        # Retrying a previous unlink must also retry its directory sync.
        if [ -e "$firewall_directory" ] || [ -L "$firewall_directory" ]; then
            plain_dir "$firewall_directory"; marker "$firewall_directory/owner" "$owner"
            sync "$firewall_directory"
        fi
        return
    fi
    plain_dir "$firewall_directory"; marker "$firewall_directory/owner" "$owner"
    inspect_firewall
    [ "$firewall_available" = yes ] || fail firewall-unavailable
    # Validate owned profile content and restore an interrupted unlink before
    # cleanup, keeping the same preconditions across supported UFW versions.
    install_firewall_profile
    ufw --force delete allow in from 0.0.0.0/0 to any app "$firewall_name" comment "$firewall_tag" >/dev/null 2>&1 || fail firewall-cleanup
    local rules
    rules=$(ufw show added 2>/dev/null) || fail firewall-inspection
    if printf '%s\n' "$rules" | grep -F -- "$firewall_name" >/dev/null; then fail firewall-cleanup; fi
    sync_firewall_rules
    # Remove the external profile before its durable intent, never the reverse.
    rm -f -- "$firewall_file"
    sync /etc/ufw/applications.d
    rm -f -- "$firewall_intent"
    sync "$firewall_directory"
}
"#;
