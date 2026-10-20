//! Atomic numeric port claims shared by every Server on a host.
use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};

use super::{host::prelude, publication::publication_vars, shell_quote};
use crate::provision::{AllocationOutcome, Request};

pub(super) const CLAIM_FUNCTIONS: &str = r#"
valid_port() {
    [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$1" -le 65535 ] || fail "${2:-claim-state}"
}
read_claim() {
    plain_dir "$claims"
    local directory=${1%/*} name=${1##*/} record previous=0 number
    plain_dir "$directory"; marker "$directory/owner" "${directory##*/}"
    plain_file "$1"
    record=$(cat "$1")
    IFS='|' read -r claim_owner claim_publication claim_generation claim_control claim_public <<< "$record"
    [ "$record" = "$claim_owner|$claim_publication|$claim_generation|$claim_control|$claim_public" ] || fail claim-state
    [ "$claim_owner" = "${directory##*/}" ] && [ "$name" = "$claim_publication.claim" ] || fail claim-state
    valid_generation "$claim_generation"
    valid_port "$claim_control"
    [ -n "$claim_public" ] || fail claim-state
    local canonical=
    for number in $claim_public; do
        valid_port "$number"
        [ "$number" -gt "$previous" ] && [ "$number" != "$claim_control" ] || fail claim-state
        canonical="${canonical:+$canonical }$number"
        previous=$number
    done
    [ "$canonical" = "$claim_public" ] || fail claim-state
}
read_own_claim() {
    claim_generation=
    claim_control=
    claim_public=
    if [ -e "$claims/$owner" ] || [ -L "$claims/$owner" ]; then
        plain_dir "$claims/$owner"; marker "$claims/$owner/owner" "$owner"
        if [ -e "$claims/$owner/$publication.claim" ] || [ -L "$claims/$owner/$publication.claim" ]; then
            read_claim "$claims/$owner/$publication.claim"
        fi
    fi
}
release_claim() {
    if [ -e "$claims/$owner/$publication.claim" ] || [ -L "$claims/$owner/$publication.claim" ]; then
        read_claim "$claims/$owner/$publication.claim"
        rm -f -- "$claims/$owner/$publication.claim"
    fi
    plain_dir "$claims"
    if [ -e "$claims/$owner" ] || [ -L "$claims/$owner" ]; then
        plain_dir "$claims/$owner"; marker "$claims/$owner/owner" "$owner"
        sync "$claims/$owner"
    fi
    sync "$claims"
}
"#;

pub(super) fn public_ports(request: &Request) -> Result<String> {
    Ok(request
        .publication
        .as_ref()
        .context("publication is required")?
        .service
        .ports
        .iter()
        .map(|port| port.port)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(" "))
}

pub(in crate::provision) fn reserve_script(request: &Request) -> Result<String> {
    let reservation = request
        .reservation
        .as_ref()
        .context("reservation is required")?;
    let publication = request
        .publication
        .as_ref()
        .context("publication is required")?;
    let range = reservation.control_port_range;
    let excluded = reservation
        .excluded_ports
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let mut script = prelude(request);
    script.push_str(&publication_vars(request)?);
    script.push_str(&format!(
        "public_ports={}\nrange_start={}\nrange_end={}\npreferred={}\nssh_port={}\nexcluded={}\n",
        shell_quote(&public_ports(request)?),
        range.start,
        range.end,
        publication.control_port,
        request.ssh_port,
        shell_quote(&excluded)
    ));
    script.push_str(r#"
reserved() {
    printf 'TUNNELLB_ALLOCATION {"kind":"reserved","controlPort":%s}\nTUNNELLB_OK\n' "$1"
    exit 0
}
reservation_changed() {
    printf 'TUNNELLB_ALLOCATION {"kind":"reservationChanged"}\nTUNNELLB_OK\n'
    exit 0
}
lock
check_global_owner; check_not_uninstalled; check_owner
check_generation_not_revoked
read_own_claim
read_current_generation
[ -z "$current_generation" ] || [ "$current_generation" = "$claim_generation" ] || fail claim-state
if [ -n "$claim_generation" ]; then
    [ "$claim_generation" = "$generation" ] && [ "$claim_public" = "$public_ports" ] || fail reservation-conflict
    sync "$claims/$owner/$publication.claim" "$claims/$owner" "$claims"
    [ "$claim_control" -ge "$range_start" ] && [ "$claim_control" -le "$range_end" ] && [ "$claim_control" != "$ssh_port" ] || reservation_changed
    case " $excluded " in *" $claim_control "*) reservation_changed ;; esac
    # Lost responses and controller restarts must recover the chosen number,
    # even when the retry proposes a different candidate or sockets are live.
    reserved "$claim_control"
fi
[ -z "$current_generation" ] && [ ! -e "$pub" ] && [ ! -L "$pub" ] || fail claim-state
declare -A used=()
plain_dir "$claims"
for directory in "$claims/"*; do
    [ -e "$directory" ] || [ -L "$directory" ] || continue
    plain_dir "$directory"; marker "$directory/owner" "${directory##*/}"
    for record in "$directory/"*.claim; do
        [ -e "$record" ] || [ -L "$record" ] || continue
        read_claim "$record"
        for number in $claim_public "$claim_control"; do
            [ -z "${used[$number]:-}" ] || fail claim-state
            used[$number]=claimed
        done
    done
done
# Snapshot once while holding the lock; candidate scanning is entirely in
# memory. Apply rechecks sockets because unrelated processes do not use flock.
sockets=$(ss -H -lntu) || fail prerequisites
while read -r protocol state received sent endpoint peer extra; do
    [ -n "$protocol" ] || continue
    case "$protocol:$state" in tcp:LISTEN|udp:UNCONN) ;; *) fail socket-state ;; esac
    [[ "$received" =~ ^[0-9]+$ && "$sent" =~ ^[0-9]+$ && "$endpoint" == *:* ]] || fail socket-state
    [ -n "${endpoint%:*}" ] && [ -n "$peer" ] && [ -z "$extra" ] || fail socket-state
    number=${endpoint##*:}
    valid_port "$number" socket-state
    used[$number]=socket
done <<< "$sockets"
for number in $public_ports; do
    if [ -n "${used[$number]:-}" ]; then
        printf 'TUNNELLB_ALLOCATION {"kind":"portConflict","port":%s}\nTUNNELLB_OK\n' "$number"
        exit 0
    fi
done
for number in $public_ports $excluded "$ssh_port"; do used[$number]=excluded; done
available() {
    [ "$1" -ge "$range_start" ] && [ "$1" -le "$range_end" ] &&
        [ -z "${used[$1]:-}" ]
}
control=
if available "$preferred"; then
    control=$preferred
else
    for ((number=range_start; number<=range_end; number++)); do
        if available "$number"; then control=$number; break; fi
    done
fi
if [ -z "$control" ]; then
    printf 'TUNNELLB_ALLOCATION {"kind":"controlRangeExhausted"}\nTUNNELLB_OK\n'
    exit 0
fi
claim_directory "$claims/$owner"
chmod 0700 "$claims/$owner"
persist_marker "$claims/$owner/$publication.claim" "$owner|$publication|$generation|$control|$public_ports"
reserved "$control"
"#);

    Ok(script)
}

pub(in crate::provision) fn parse_allocation(output: &str) -> Result<AllocationOutcome> {
    ensure!(
        output.len() <= 64 * 1024,
        "remote allocation output is too large"
    );
    let mut records = output
        .lines()
        .filter_map(|line| line.strip_prefix("TUNNELLB_ALLOCATION "));
    let record = records
        .next()
        .context("remote worker returned no allocation")?;
    ensure!(record.len() <= 128, "remote allocation record is too large");
    ensure!(
        records.next().is_none(),
        "remote worker returned multiple allocations"
    );
    let allocation: AllocationOutcome = serde_json::from_str(record)
        .map_err(|_| anyhow::anyhow!("remote worker returned an invalid allocation"))?;
    // Serde's internally tagged unit variants can otherwise accept extra
    // fields even with deny_unknown_fields on the enum.
    let fields: serde_json::Value = serde_json::from_str(record)
        .map_err(|_| anyhow::anyhow!("remote worker returned an invalid allocation"))?;
    ensure!(
        fields == serde_json::to_value(&allocation)?,
        "remote worker returned unexpected allocation fields"
    );
    ensure!(
        !matches!(
            allocation,
            AllocationOutcome::Reserved { control_port: 0 }
                | AllocationOutcome::PortConflict { port: 0 }
        ),
        "remote worker returned a zero port"
    );

    Ok(allocation)
}
