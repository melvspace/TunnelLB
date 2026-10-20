use super::*;
use crate::{
    api::{PortRange, Protocol},
    provision::{AllocationOutcome, Request},
    transport::{self, Credentials, FRP_VERSION},
};

fn owner_request(owner: &str, port: u16) -> Request {
    let mut request = request(Operation::Reserve);
    request.server_uid = owner.into();
    let publication = request.publication.as_mut().unwrap();
    publication.server_uid = owner.into();
    publication.service.ports.truncate(1);
    publication.service.ports[0].port = port;
    refresh_config(&mut request);

    request
}

fn refresh_config(request: &mut Request) {
    let credentials = Credentials {
        token: "a".repeat(64),
        certificate_pem: request.server_certificate.clone().unwrap(),
        private_key_pem: request.server_private_key.clone().unwrap(),
    };
    request.server_config = Some(
        transport::server_config(request.publication.as_ref().unwrap(), &credentials).unwrap(),
    );
}

fn choose(host: &TestHost, request: &mut Request) -> u16 {
    let AllocationOutcome::Reserved { control_port } = host.reserve(request) else {
        panic!("reservation failed");
    };
    request.publication.as_mut().unwrap().control_port = control_port;
    refresh_config(request);

    control_port
}

fn claim(host: &TestHost, request: &Request) -> std::path::PathBuf {
    host.path(&format!(
        "state/claims/{}/{}.claim",
        request.server_uid,
        request.publication.as_ref().unwrap().id
    ))
}

#[test]
fn two_owners_apply_and_partial_uninstall_preserves_the_other_owner() {
    let host = TestHost::new();
    let mut first = owner_request("first", 443);
    let mut second = owner_request("second", 8443);
    host.enroll(&first);
    host.enroll(&second);
    assert_ne!(choose(&host, &mut first), choose(&host, &mut second));
    host.success(apply_script(&first).unwrap());
    host.success(apply_script(&second).unwrap());
    let second_claim = std::fs::read(claim(&host, &second)).unwrap();
    let second_payload = host.path("state/second/publications/pub-0123/frps.toml");
    let second_contents = std::fs::read(&second_payload).unwrap();

    host.flag("fail-stop");
    host.failure(uninstall_script(&first).unwrap(), "stop");
    assert!(claim(&host, &first).exists());
    assert!(host.active(&first).exists());
    host.failure(reserve_script(&first).unwrap(), "server-revoked");
    std::fs::remove_file(host.path("fail-stop")).unwrap();
    host.flag("fail-owned-delete");
    host.failure(uninstall_script(&first).unwrap(), "command");
    assert!(!claim(&host, &first).exists());
    host.success(uninstall_script(&first).unwrap());

    assert!(!host.active(&first).exists());
    assert!(host.active(&second).exists());
    assert_eq!(std::fs::read(claim(&host, &second)).unwrap(), second_claim);
    assert_eq!(std::fs::read(second_payload).unwrap(), second_contents);
    assert!(host.path(&format!("opt/{FRP_VERSION}/frps")).exists());
    host.success(apply_script(&second).unwrap());
}

#[test]
fn interrupted_claim_commit_replays_whole_record_without_partial_port_claims() {
    let host = TestHost::new();
    let request = request(Operation::Reserve);
    host.enroll(&request);
    host.flag("fail-claim-sync");
    host.failure(reserve_script(&request).unwrap(), "command");
    assert!(claim(&host, &request).exists());
    assert_eq!(
        host.reserve(&request),
        AllocationOutcome::Reserved {
            control_port: 22000
        }
    );
    // Uncommitted directory/file stages are never authoritative claims.
    let pending = host.path("state/claims/.claim.interrupted");
    std::fs::create_dir(&pending).unwrap();
    std::fs::write(pending.join("owner"), "incomplete").unwrap();
    std::fs::write(
        host.path("state/claims/server-uid/ignored.claim.pending.123"),
        "incomplete",
    )
    .unwrap();
    let second = owner_request("second", 8443);
    host.enroll(&second);
    assert!(matches!(
        host.reserve(&second),
        AllocationOutcome::Reserved { .. }
    ));
}

#[test]
fn concurrent_reservations_serialize_numeric_conflicts_and_disjoint_controls() {
    for overlapping in [false, true] {
        let host = TestHost::new();
        let first = owner_request("first", 443);
        let mut second = owner_request("second", if overlapping { 443 } else { 8443 });
        second.publication.as_mut().unwrap().service.ports[0].protocol = Protocol::Udp;
        host.enroll(&first);
        host.enroll(&second);
        let start = std::sync::Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let left = scope.spawn(|| {
                start.wait();
                host.reserve(&first)
            });
            let right = scope.spawn(|| {
                start.wait();
                host.reserve(&second)
            });
            (left.join().unwrap(), right.join().unwrap())
        });

        if overlapping {
            assert!(matches!(
                results,
                (
                    AllocationOutcome::Reserved { .. },
                    AllocationOutcome::PortConflict { port: 443 }
                ) | (
                    AllocationOutcome::PortConflict { port: 443 },
                    AllocationOutcome::Reserved { .. }
                )
            ));
            assert_ne!(
                claim(&host, &first).exists(),
                claim(&host, &second).exists()
            );
        } else {
            let (
                AllocationOutcome::Reserved { control_port: left },
                AllocationOutcome::Reserved {
                    control_port: right,
                },
            ) = results
            else {
                panic!("disjoint reservation failed");
            };
            assert_ne!(left, right);
            assert!(claim(&host, &first).exists() && claim(&host, &second).exists());
        }
    }
}

#[test]
fn replay_recovers_chosen_control_and_rechecks_current_policy() {
    let host = TestHost::new();
    let mut request = request(Operation::Reserve);
    request.reservation.as_mut().unwrap().excluded_ports = vec![20002, 20001, 20002];
    host.enroll(&request);
    let original = host.reserve(&request);
    let before = std::fs::read(claim(&host, &request)).unwrap();
    let publication = request.publication.as_mut().unwrap();
    publication.control_port = 25000;
    publication.service.ports.reverse();
    request.reservation.as_mut().unwrap().excluded_ports = vec![20001, 20002];
    // This replay runs a new shell with no in-memory state, after its listeners
    // have appeared. The durable result must win over the proposed candidate.
    std::fs::write(host.path("sockets-tcp-22000"), "occupied").unwrap();
    assert_eq!(host.reserve(&request), original);

    let mut changed = request.clone();
    changed
        .reservation
        .as_mut()
        .unwrap()
        .control_port_range
        .start += 1;
    assert_eq!(host.reserve(&changed), original);
    changed = request.clone();
    changed
        .reservation
        .as_mut()
        .unwrap()
        .excluded_ports
        .push(20003);
    assert_eq!(host.reserve(&changed), original);
    changed
        .reservation
        .as_mut()
        .unwrap()
        .excluded_ports
        .push(22000);
    assert_eq!(
        host.reserve(&changed),
        AllocationOutcome::ReservationChanged
    );
    changed = request.clone();
    changed
        .reservation
        .as_mut()
        .unwrap()
        .control_port_range
        .start = 22001;
    assert_eq!(
        host.reserve(&changed),
        AllocationOutcome::ReservationChanged
    );
    changed = request.clone();
    changed.publication.as_mut().unwrap().service.ports[0].port = 8443;
    host.failure(reserve_script(&changed).unwrap(), "reservation-conflict");
    changed = request.clone();
    changed.generation = Some("b".repeat(64));
    host.failure(reserve_script(&changed).unwrap(), "reservation-conflict");
    assert_eq!(std::fs::read(claim(&host, &request)).unwrap(), before);
}

#[test]
fn reservations_cover_public_control_cross_protocol_sockets_and_exhaustion() {
    let host = TestHost::new();
    let first = owner_request("first", 443);
    let mut second = owner_request("second", 8443);
    host.enroll(&first);
    host.enroll(&second);
    host.reserve(&first);
    let publication = second.publication.as_mut().unwrap();
    publication.service.ports[0].port = 22000;
    publication.service.ports[0].protocol = Protocol::Udp;
    assert_eq!(
        host.reserve(&second),
        AllocationOutcome::PortConflict { port: 22000 }
    );
    second.publication.as_mut().unwrap().service.ports[0].port = 8443;
    std::fs::write(host.path("sockets-udp-8443"), "foreign socket").unwrap();
    assert_eq!(
        host.reserve(&second),
        AllocationOutcome::PortConflict { port: 8443 }
    );
    std::fs::remove_file(host.path("sockets-udp-8443")).unwrap();
    second.reservation.as_mut().unwrap().control_port_range = PortRange {
        start: 22000,
        end: 22003,
    };
    second.reservation.as_mut().unwrap().excluded_ports = vec![22001];
    std::fs::write(host.path("sockets-udp-22002"), "foreign socket").unwrap();
    std::fs::write(host.path("sockets-tcp-22003"), "foreign socket").unwrap();
    assert_eq!(
        host.reserve(&second),
        AllocationOutcome::ControlRangeExhausted
    );
    assert!(!claim(&host, &second).exists());
    std::fs::remove_file(host.path("sockets-tcp-22003")).unwrap();
    assert_eq!(
        host.reserve(&second),
        AllocationOutcome::Reserved {
            control_port: 22003
        }
    );
}

#[test]
fn socket_snapshot_is_numeric_strict_and_sampled_once_per_reservation() {
    let host = TestHost::new();
    let request = owner_request("first", 443);
    host.enroll(&request);
    let snapshot = host.path("sockets-snapshot");
    std::fs::write(&snapshot, "udp UNCONN 0 0 [::]:443 [::]:*\n").unwrap();
    assert_eq!(
        host.reserve(&request),
        AllocationOutcome::PortConflict { port: 443 }
    );
    std::fs::write(
        &snapshot,
        "tcp LISTEN 0 4096 *:22000 *:*\nudp UNCONN 0 0 127.0.0.1:20000 *:*\n",
    )
    .unwrap();
    assert_eq!(
        host.reserve(&request),
        AllocationOutcome::Reserved {
            control_port: 20001
        }
    );
    assert_eq!(
        std::fs::read_to_string(host.path("socket-probes")).unwrap(),
        "-H -lntu\n-H -lntu\n"
    );
    let second = owner_request("second", 8443);
    host.enroll(&second);

    for malformed in [
        "tcp LISTEN 0 0 *:0 *:*",
        "tcp LISTEN 0 0 *:65536 *:*",
        "tcp LISTEN 0 0 *:http *:*",
        "tcp LISTEN 0 0 443 *:*",
        "tcp LISTEN 0 0 *:0443 *:*",
        "udp UNCONN invalid 0 *:443 *:*",
        "tcp UNKNOWN 0 0 *:443 *:*",
        "tcp LISTEN 0 0 *:443",
        "tcp LISTEN 0 0 *:443 *:* unexpected",
    ] {
        std::fs::write(&snapshot, malformed).unwrap();
        host.failure(reserve_script(&second).unwrap(), "socket-state");
        assert!(!claim(&host, &second).exists());
    }
}

#[test]
fn reserved_only_cleanup_and_stale_remove_leave_replacement_claim_untouched() {
    let host = TestHost::new();
    let old = owner_request("first", 443);
    host.enroll(&old);
    host.reserve(&old);
    host.success(remove_script(&old).unwrap());
    assert!(!claim(&host, &old).exists());
    host.failure(reserve_script(&old).unwrap(), "generation-revoked");
    let replacement = owner_request("first", 443);
    host.reserve(&replacement);
    let before = std::fs::read(claim(&host, &replacement)).unwrap();
    host.success(remove_script(&old).unwrap());
    assert_eq!(std::fs::read(claim(&host, &replacement)).unwrap(), before);
    host.success(uninstall_script(&replacement).unwrap());
    assert!(!claim(&host, &replacement).exists());
    host.failure(reserve_script(&replacement).unwrap(), "server-revoked");
}

#[test]
fn apply_requires_matching_claim_and_binary_cache_is_immutable() {
    let host = TestHost::new();
    let request = owner_request("first", 443);
    host.enroll(&request);
    host.failure(apply_script(&request).unwrap(), "reservation-required");
    host.reserve(&request);
    let mut changed = request.clone();
    changed.publication.as_mut().unwrap().control_port += 1;
    host.failure(apply_script(&changed).unwrap(), "reservation-conflict");
    changed = request.clone();
    changed.publication.as_mut().unwrap().service.ports[0].port += 1;
    host.failure(apply_script(&changed).unwrap(), "reservation-conflict");
    let binary = host.path(&format!("opt/{FRP_VERSION}/frps"));
    std::fs::write(&binary, "unexpected executable").unwrap();
    host.failure(
        enroll_script(&request, Some(b"#!/bin/sh\nexit 0\n"), AMD64_SHA256).unwrap(),
        "checksum",
    );
    assert_eq!(
        std::fs::read_to_string(binary).unwrap(),
        "unexpected executable"
    );
}

#[test]
fn malformed_foreign_claims_and_orphan_processes_cannot_release_capacity() {
    let host = TestHost::new();
    let first = owner_request("first", 443);
    let second = owner_request("second", 8443);
    host.enroll(&first);
    host.enroll(&second);
    host.reserve(&first);
    let record = std::fs::read(claim(&host, &first)).unwrap();
    std::fs::write(claim(&host, &first), "partial").unwrap();
    host.failure(reserve_script(&second).unwrap(), "claim-state");
    std::fs::write(claim(&host, &first), record).unwrap();
    std::fs::remove_file(host.path("systemd/tunnellb-first@.service")).unwrap();
    std::fs::write(host.active(&first), "123\n").unwrap();
    host.failure(remove_script(&first).unwrap(), "unit-owner");
    assert!(claim(&host, &first).exists());
    host.failure(uninstall_script(&first).unwrap(), "unit-owner");
    assert!(claim(&host, &first).exists());
}

#[test]
fn allocation_parser_is_strict_bounded_and_does_not_echo_untrusted_output() {
    assert_eq!(
        parse_allocation(
            "TUNNELLB_ALLOCATION {\"kind\":\"reserved\",\"controlPort\":22000}\nTUNNELLB_OK\n"
        )
        .unwrap(),
        AllocationOutcome::Reserved {
            control_port: 22000
        }
    );

    for output in [
        "TUNNELLB_OK".to_owned(),
        "TUNNELLB_ALLOCATION {\"kind\":\"reserved\",\"control_port\":22000}".into(),
        "TUNNELLB_ALLOCATION {\"kind\":\"reserved\",\"controlPort\":0}".into(),
        "TUNNELLB_ALLOCATION {\"kind\":\"portConflict\",\"port\":65536}".into(),
        "TUNNELLB_ALLOCATION {\"kind\":\"controlRangeExhausted\",\"secret\":\"RAW_SECRET\"}".into(),
        "TUNNELLB_ALLOCATION {\"kind\":\"controlRangeExhausted\"}\n".repeat(2),
        "RAW_SECRET".repeat(8000),
    ] {
        let error = parse_allocation(&output).unwrap_err().to_string();
        assert!(!error.contains("RAW_SECRET"));
    }
}
