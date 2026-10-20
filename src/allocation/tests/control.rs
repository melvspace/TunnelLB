use super::*;
use crate::api::Publication;

fn publication(ledger: &mut Ledger, server: &Server) -> Publication {
    let service = service("a", &[(Protocol::Tcp, 443), (Protocol::Udp, 443)]);
    let control_port = ledger.allocate("a", &service, server).unwrap();
    Publication {
        id: "a".into(),
        server_name: server.metadata.name.clone().unwrap(),
        server_uid: server.metadata.uid.clone().unwrap(),
        server_address: server.spec.address.parse().unwrap(),
        control_port,
        service,
    }
}

#[test]
fn exclusions_preserve_local_numbers_and_policy_but_omit_our_control() {
    let mut server = server();
    server.spec.reserved_ports = vec![8080];
    let mut ledger = Ledger::default();
    let mut publication = publication(&mut ledger, &server);
    server.spec.reserved_ports.push(8443);
    ledger
        .allocate("b", &service("b", &[(Protocol::Udp, 53)]), &server)
        .unwrap();
    server.spec.reserved_ports = vec![9443];
    server.spec.ssh.port = 2222;
    // After confirmation, the record may still contain the provisional control.
    ledger.allocations.get_mut("a").unwrap().control_port = 20003;
    publication.service.ports.reverse();
    publication.service.ports[0].name = "renamed".into();
    let before = ledger.clone();
    assert_eq!(
        ledger.control_exclusions(&server, &publication).unwrap(),
        vec![22, 53, 443, 2222, 8080, 8443, 9443, 20001]
    );
    assert_eq!(ledger, before);
}

#[test]
fn confirmation_changes_only_control_and_retries_a_stale_record() {
    let server = server();
    let mut ledger = Ledger::default();
    let publication = publication(&mut ledger, &server);
    ledger
        .allocate("b", &service("b", &[(Protocol::Tcp, 8443)]), &server)
        .unwrap();
    let mut expected = ledger.clone();
    expected.allocations.get_mut("a").unwrap().control_port = 20003;
    ledger
        .confirm_control(&server, &publication, 20003)
        .unwrap();
    assert_eq!(ledger, expected);
    ledger
        .confirm_control(&server, &publication, 20003)
        .unwrap();
    assert_eq!(ledger, expected);
    assert_eq!(
        ledger.allocate("a", &publication.service, &server).unwrap(),
        20003
    );
}

#[test]
fn confirmation_rejects_invalid_or_occupied_controls_without_mutation() {
    let mut server = server();
    server.spec.control_port_range.end = 30000;
    server.spec.ssh.port = 22222;
    server.spec.reserved_ports = vec![22223];
    let mut ledger = Ledger::default();
    let mut publication = publication(&mut ledger, &server);
    // Keep public collisions inside the allowed control range.
    publication.service.ports[0].port = 22224;
    publication.service.ports[1].port = 22224;
    ledger.release("a");
    publication.control_port = ledger.allocate("a", &publication.service, &server).unwrap();
    ledger
        .allocate("b", &service("b", &[(Protocol::Udp, 22225)]), &server)
        .unwrap();

    for port in [0, 19999, 30001, 22222, 22223, 22224, 22225, 20001] {
        let before = ledger.clone();
        assert!(ledger.confirm_control(&server, &publication, port).is_err());
        assert_eq!(ledger, before, "failed confirmation of {port}");
    }

    ledger.allocations.get_mut("a").unwrap().control_port = 20002;
    let before = ledger.clone();
    assert!(
        ledger
            .confirm_control(&server, &publication, 20003)
            .is_err()
    );
    assert_eq!(ledger, before, "a third control must not be overwritten");
}

#[test]
fn confirmation_and_exclusions_require_exact_owner_and_public_reservations() {
    let server = server();
    let mut ledger = Ledger::default();
    let publication = publication(&mut ledger, &server);

    for problem in [
        "missing",
        "namespace",
        "name",
        "uid",
        "server-name",
        "server-uid",
        "address",
        "public",
        "protocol",
        "duplicate",
    ] {
        let mut changed = publication.clone();
        match problem {
            "missing" => changed.id = "missing".into(),
            "namespace" => changed.service.namespace = "other".into(),
            "name" => changed.service.name = "other".into(),
            "uid" => changed.service.uid = "other".into(),
            "server-name" => changed.server_name = "other".into(),
            "server-uid" => changed.server_uid = "other".into(),
            "address" => changed.server_address = "203.0.113.11".parse().unwrap(),
            "public" => changed.service.ports[0].port = 8443,
            "protocol" => {
                changed.service.ports.remove(0);
            }
            _ => changed.service.ports.push(changed.service.ports[0].clone()),
        }

        let before = ledger.clone();
        assert!(ledger.control_exclusions(&server, &changed).is_err());
        // Selecting the already-stored control must still check ownership.
        assert!(
            ledger
                .confirm_control(&server, &changed, publication.control_port)
                .is_err()
        );
        assert_eq!(ledger, before, "failed confirmation of {problem}");
    }
}

#[test]
fn corrupt_ledgers_and_invalid_server_policy_cannot_be_confirmed() {
    let server = server();
    let mut ledger = Ledger::default();
    let publication = publication(&mut ledger, &server);
    ledger
        .allocate("b", &service("b", &[(Protocol::Tcp, 8443)]), &server)
        .unwrap();

    for problem in [
        "corrupt",
        "overlap",
        "address",
        "server",
        "range",
        "zero-ssh",
        "zero-reserved",
        "reserved-public",
    ] {
        let mut candidate = ledger.clone();
        let mut server = server.clone();
        match problem {
            "corrupt" => candidate.allocations.get_mut("b").unwrap().control_port = 0,
            "overlap" => {
                candidate.allocations.get_mut("b").unwrap().control_port = publication.control_port;
            }
            "address" => server.spec.address = "example.com".into(),
            "server" => server.metadata.uid = Some("recreated".into()),
            "range" => server.spec.control_port_range.start = 0,
            "zero-ssh" => server.spec.ssh.port = 0,
            "zero-reserved" => server.spec.reserved_ports.push(0),
            _ => server.spec.reserved_ports.push(443),
        }

        let before = candidate.clone();
        assert!(candidate.control_exclusions(&server, &publication).is_err());
        assert!(
            candidate
                .confirm_control(&server, &publication, 20003)
                .is_err()
        );
        assert_eq!(candidate, before, "failed confirmation of {problem}");
    }
}
