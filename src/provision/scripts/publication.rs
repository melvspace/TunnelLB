//! Immutable publication installation and generation-specific revocation.
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use super::{
    digest,
    host::{prelude, systemd_unit},
    reservation::public_ports,
    shell_quote, upload,
};

use crate::provision::{Request, request::required_field};

pub(super) fn publication_vars(request: &Request) -> Result<String> {
    let publication = request
        .publication
        .as_ref()
        .context("publication is required")?;
    let generation = request
        .generation
        .as_deref()
        .context("credential generation is required")?;

    Ok(format!(
        "publication={}\ngeneration={}\npub=\"$owned/publications/$publication\"\nunit=\"tunnellb-$owner@$publication.service\"\n",
        shell_quote(&publication.id),
        shell_quote(generation)
    ))
}

pub(in crate::provision) fn apply_script(request: &Request) -> Result<String> {
    let publication = request
        .publication
        .as_ref()
        .context("publication is required")?;
    let config = required_field(&request.server_config, "server configuration")?;
    let certificate = required_field(&request.server_certificate, "server certificate")?;
    let key = required_field(&request.server_private_key, "server private key")?;
    let mut script = prelude(request);
    script.push_str(&publication_vars(request)?);
    script.push_str(&format!(
        "configuration_hash={}\npublic_ports={}\ncontrol_port={}\n",
        shell_quote(&digest(config.as_bytes())),
        shell_quote(&public_ports(request)?),
        publication.control_port,
    ));
    script.push_str(
        r#"
lock
check_global_owner; check_not_uninstalled
check_generation_not_revoked
check_owner; check_binary_owner; check_template
read_own_claim
[ -n "$claim_generation" ] || fail reservation-required
[ "$claim_generation" = "$generation" ] && [ "$claim_control" = "$control_port" ] && [ "$claim_public" = "$public_ports" ] || fail reservation-conflict
read_current_generation
[ -z "$current_generation" ] || [ "$current_generation" = "$generation" ] || fail generation-conflict
[ -z "$current_configuration_hash" ] || [ "$current_configuration_hash" = "$configuration_hash" ] || fail generation-conflict
plain_dir "$owned/publications"; plain_file "$binary"
check_unit
case "$(uname -m)" in
    x86_64) expected_binary=$amd64_digest ;;
    aarch64|arm64) expected_binary=$arm64_digest ;;
    *) fail architecture ;;
esac
[ "$(sha256sum "$binary" | cut -d' ' -f1)" = "$expected_binary" ] || fail checksum
if [ -e "$pub" ] || [ -L "$pub" ]; then
    [ -n "$current_generation" ] || fail generation-state
    check_publication
fi
stage=$(mktemp -d "$owned/.apply.XXXXXXXX")
trap 'rm -rf --one-file-system -- "$stage"' EXIT
"#,
    );
    upload(&mut script, "\"$stage/frps.toml\"", config.as_bytes());
    upload(&mut script, "\"$stage/tls.crt\"", certificate.as_bytes());
    upload(&mut script, "\"$stage/tls.key\"", key.as_bytes());
    let mut hasher = Sha256::new();

    for bytes in [
        config.as_bytes(),
        certificate.as_bytes(),
        key.as_bytes(),
        systemd_unit(&request.machine_uid).as_bytes(),
    ] {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }

    script.push_str(&format!(
        "content_hash={}\n",
        shell_quote(&hex::encode(hasher.finalize()))
    ));
    script.push_str(r#"
# Verify a staged configuration without exposing tokens in output.
sed "s|$pub/tls.crt|$stage/tls.crt|g; s|$pub/tls.key|$stage/tls.key|g" "$stage/frps.toml" > "$stage/verify.toml"
"$binary" verify -c "$stage/verify.toml" >/dev/null 2>&1 || fail configuration
own_pid=$(systemctl show "$unit" --property=MainPID --value)
check_port() {
    proto=$1; number=$2
    if [ "$proto" = tcp ]; then sockets=$(ss -H -lntp "sport = :$number"); else sockets=$(ss -H -lnup "sport = :$number"); fi
    if [ -z "$sockets" ]; then return; fi
    [ "$own_pid" -gt 0 ] || fail occupied-port
    while IFS= read -r socket; do
        pids=$(printf '%s\n' "$socket" | grep -o 'pid=[0-9]*' | cut -d= -f2) || fail occupied-port
        [ -n "$pids" ] || fail occupied-port
        for pid in $pids; do [ "$pid" = "$own_pid" ] || fail occupied-port; done
    done <<< "$sockets"
}
"#);
    script.push_str(r#"
for number in $public_ports "$control_port"; do
    check_port tcp "$number"
    check_port udp "$number"
done
# Bind the immutable configuration to the existing reservation before payload
# creation. Only a completed matching Remove releases the host-wide claim.
claim_directory "$generations"
chmod 0700 "$generations"
persist_marker "$generations/$publication" "$generation:$configuration_hash"
if [ ! -d "$pub" ]; then
    mkdir -m 0750 "$stage/publication"
    chown "root:$account" "$stage/publication"
    printf '%s:%s\n' "$owner" "$publication" > "$stage/publication/owner"
    mv -T -- "$stage/publication" "$pub"
fi
unchanged=yes
for file in frps.toml tls.crt tls.key; do
    if [ -e "$pub/$file" ] || [ -L "$pub/$file" ]; then plain_file "$pub/$file"; fi
    if [ ! -f "$pub/$file" ] || ! cmp -s "$stage/$file" "$pub/$file"; then unchanged=no; fi
done
if [ "$unchanged" = no ]; then
    for file in frps.toml tls.crt tls.key; do
        chown "root:$account" "$stage/$file"
        chmod 0640 "$stage/$file"
        mv -fT "$stage/$file" "$pub/$file"
    done
fi
chown "root:$account" "$pub" "$pub/frps.toml" "$pub/tls.crt" "$pub/tls.key"
chmod 0750 "$pub"
chmod 0640 "$pub/frps.toml" "$pub/tls.crt" "$pub/tls.key"
systemctl enable "$unit" >/dev/null 2>&1 || fail start
if [ "$unchanged" = yes ] && [ -f "$pub/content.sha256" ] && [ "$(cat "$pub/content.sha256")" = "$content_hash" ] && systemctl is-active --quiet "$unit"; then
    printf 'TUNNELLB_OK\n'
    exit 0
fi
systemctl reset-failed "$unit" >/dev/null 2>&1 || true
systemctl restart "$unit" >/dev/null 2>&1 || fail start
# A Type=simple unit can briefly be active before a bind/certificate failure.
sleep 2
systemctl is-active --quiet "$unit" || fail start
printf '%s\n' "$content_hash" > "$stage/content.sha256"
mv -fT "$stage/content.sha256" "$pub/content.sha256"
printf 'TUNNELLB_OK\n'
"#);

    Ok(script)
}

pub(in crate::provision) fn remove_script(request: &Request) -> Result<String> {
    let mut script = prelude(request);
    script.push_str(&publication_vars(request)?);
    script.push_str(
        r#"
lock
initialize_host
if [ -e "$retired" ] || [ -L "$retired" ]; then
    persist_marker "$retired" "$owner"
    if [ -e "$owned" ] || [ -L "$owned" ]; then check_cleanup_owner; fi
    # Terminal Machine revocation already fences every generation, but a
    # previous Uninstall may have failed before stopping this publication.
    cleanup_publication
    release_claim
    printf 'TUNNELLB_OK\n'; exit 0
fi
# Remove must also fence an Apply that has not installed anything yet.
claim_directory "$owned"
claim_directory "$revocations"
chmod 0700 "$revocations"
persist_marker "$revocations/$publication-$generation" "$owner:$publication:$generation"
read_own_claim
read_current_generation
[ -z "$current_generation" ] || [ "$current_generation" = "$claim_generation" ] || fail claim-state
if [ -n "$claim_generation" ] && [ "$claim_generation" != "$generation" ]; then
    printf 'TUNNELLB_OK\n'; exit 0
fi
if [ -n "$current_generation" ] && [ "$current_generation" != "$generation" ]; then
    # An old Remove may arrive after replacement. It revokes only the old
    # generation and must leave the new unit and payload untouched.
    printf 'TUNNELLB_OK\n'; exit 0
fi
if [ -z "$claim_generation" ] && { [ -e "$unitfile" ] || [ -L "$unitfile" ]; }; then
    check_unit
    if systemctl is-active --quiet "$unit"; then fail generation-state; fi
fi
if [ -z "$claim_generation" ] && { [ -n "$current_generation" ] || [ -e "$pub" ] || [ -L "$pub" ]; }; then
    fail claim-state
fi
cleanup_publication
if [ -e "$generations/$publication" ] || [ -L "$generations/$publication" ]; then
    plain_file "$generations/$publication"
    rm -f -- "$generations/$publication"
fi
if [ -e "$generations" ] || [ -L "$generations" ]; then
    plain_dir "$generations"; marker "$generations/owner" "$owner"
    sync "$generations"
fi
release_claim
printf 'TUNNELLB_OK\n'
"#,
    );

    Ok(script)
}
