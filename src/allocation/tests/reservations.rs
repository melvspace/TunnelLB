use super::*;

#[test]
fn publication_numbers_are_exclusive_and_conflicts_are_atomic() {
    let server = server();

    for victim_protocol in [Protocol::Tcp, Protocol::Udp] {
        for attacker_protocol in [Protocol::Tcp, Protocol::Udp] {
            let mut ledger = Ledger::default();
            ledger
                .allocate(
                    "victim",
                    &service("victim", &[(victim_protocol, 443)]),
                    &server,
                )
                .unwrap();
            // A free number sorts before the collision. A failed multi-port
            // request must not retain it, even when the protocols differ.
            let attacker = service(
                "attacker",
                &[(attacker_protocol, 80), (attacker_protocol, 443)],
            );
            let error = assert_rejected(&mut ledger, "attacker", &attacker, &server)
                .context("allocating publication");
            assert!(matches!(
                error.downcast_ref::<AllocationConflict>(),
                Some(AllocationConflict::PortUnavailable { port: 443 })
            ));
            // Publication identity still isolates two copies of the same Service.
            assert_rejected(
                &mut ledger,
                "same-service-other-publication",
                &service("victim", &[(attacker_protocol, 443)]),
                &server,
            );
            let disjoint = service("attacker", &[(attacker_protocol, 80)]);
            assert_eq!(
                ledger.allocate("attacker", &disjoint, &server).unwrap(),
                20001
            );
        }
    }
}

#[test]
fn control_and_public_numbers_remain_distinct_across_protocols_and_retries() {
    let server = server();

    for (ports, expected_control) in [
        (vec![(Protocol::Tcp, 20000)], 20001),
        (vec![(Protocol::Udp, 20000)], 20001),
        (vec![(Protocol::Tcp, 20000), (Protocol::Udp, 20000)], 20001),
        (vec![(Protocol::Udp, 20001)], 20000),
    ] {
        let mut ledger = Ledger::default();
        let request = service("a", &ports);
        assert_eq!(
            ledger.allocate("a", &request, &server).unwrap(),
            expected_control
        );
        let before = ledger.clone();
        assert_eq!(
            ledger.allocate("a", &request, &server).unwrap(),
            expected_control
        );
        assert_eq!(ledger, before);

        for protocol in [Protocol::Tcp, Protocol::Udp] {
            for port in [ports[0].1, expected_control] {
                assert_rejected(
                    &mut ledger,
                    "b",
                    &service("b", &[(protocol, port)]),
                    &server,
                );
            }
        }

        assert_eq!(
            ledger
                .allocate("b", &service("b", &[(Protocol::Tcp, 443)]), &server)
                .unwrap(),
            20002
        );
    }
}

#[test]
fn ssh_and_admin_reservations_exclude_both_protocols_and_control() {
    let mut server = server();
    server.spec.ssh.port = 20000;
    server.spec.reserved_ports = vec![20001, 8443];
    let mut ledger = Ledger::default();

    for protocol in [Protocol::Tcp, Protocol::Udp] {
        for port in [20000, 20001, 8443] {
            let error = assert_rejected(
                &mut ledger,
                "bad",
                &service("bad", &[(protocol, port)]),
                &server,
            );
            assert!(matches!(error.downcast_ref::<AllocationConflict>(),
                Some(AllocationConflict::PortUnavailable { port: unavailable }) if *unavailable == port));
        }
    }

    assert_eq!(
        ledger
            .allocate("p", &service("a", &[(Protocol::Tcp, 443)]), &server)
            .unwrap(),
        20002
    );
}

#[test]
fn exhaustion_is_atomic_and_release_makes_control_and_public_ports_reusable() {
    let mut server = server();
    server.spec.control_port_range.end = 20000;
    let mut ledger = Ledger::default();
    ledger
        .allocate("a", &service("a", &[(Protocol::Tcp, 443)]), &server)
        .unwrap();
    let next = service("b", &[(Protocol::Udp, 53)]);
    let error = assert_rejected(&mut ledger, "b", &next, &server);
    assert!(matches!(
        error.downcast_ref::<AllocationConflict>(),
        Some(AllocationConflict::ControlRangeExhausted)
    ));
    ledger.release("missing");
    assert_eq!(ledger.publication_ids(), vec!["a"]);
    ledger.release("a");
    ledger.release("a");
    assert!(ledger.is_empty());
    assert_eq!(ledger.allocate("b", &next, &server).unwrap(), 20000);
    ledger.release("b");
    assert_eq!(
        ledger
            .allocate("c", &service("c", &[(Protocol::Tcp, 443)]), &server)
            .unwrap(),
        20000
    );
}

#[test]
fn own_public_ports_can_exhaust_control_range_without_leaking_reservations() {
    let mut server = server();
    server.spec.control_port_range.end = 20001;

    for protocol in [Protocol::Tcp, Protocol::Udp] {
        let mut ledger = Ledger::default();
        assert_rejected(
            &mut ledger,
            "p",
            &service("a", &[(protocol, 20000), (protocol, 20001)]),
            &server,
        );
    }
}

#[test]
fn newly_declared_exclusions_cannot_overlap_existing_public_or_control_ports() {
    let server = server();
    let mut ledger = Ledger::default();
    ledger
        .allocate("a", &service("a", &[(Protocol::Udp, 443)]), &server)
        .unwrap();

    for port in [443, 20000] {
        for ssh in [false, true] {
            let mut changed = server.clone();

            if ssh {
                changed.spec.ssh.port = port;
            } else {
                changed.spec.reserved_ports = vec![port];
            }

            let error = assert_rejected(
                &mut ledger,
                "b",
                &service("b", &[(Protocol::Tcp, 8080)]),
                &changed,
            );
            assert!(matches!(
                error.downcast_ref::<AllocationConflict>(),
                Some(AllocationConflict::ReservedPorts { .. })
            ));
        }
    }
}

#[test]
fn typed_requests_do_not_bypass_validation() {
    let server = server();
    let original = service("a", &[(Protocol::Tcp, 443)]);
    let mut ledger = Ledger::default();

    for id in ["", " ", "bad id", "bad\nid"] {
        assert_rejected(&mut ledger, id, &original, &server);
    }

    let mut changes = vec![original.clone(); 8];
    changes[0].namespace.clear();
    changes[1].name.clear();
    changes[2].uid.clear();
    changes[3].uid = " bad-uid".into();
    changes[4].ports.clear();
    changes[5].ports[0].port = 0;
    changes[6].ports.push(original.ports[0].clone());
    let mut duplicate = original.ports[0].clone();
    duplicate.name = "different-name".into();
    duplicate.proxy_protocol = ProxyProtocol::V2;
    changes[7].ports.push(duplicate);

    for changed in changes {
        assert_rejected(&mut ledger, "p", &changed, &server);
    }

    assert!(ledger.is_empty());
}

#[test]
fn control_range_includes_the_last_u16_port_without_overflow() {
    let mut server = server();
    server.spec.control_port_range = PortRange {
        start: u16::MAX,
        end: u16::MAX,
    };
    let mut ledger = Ledger::default();
    assert_rejected(
        &mut ledger,
        "udp-exhausts-range",
        &service("udp", &[(Protocol::Udp, u16::MAX)]),
        &server,
    );
    assert_eq!(
        ledger
            .allocate("p", &service("a", &[(Protocol::Tcp, 443)]), &server)
            .unwrap(),
        u16::MAX
    );
    assert_rejected(
        &mut ledger,
        "q",
        &service("b", &[(Protocol::Tcp, 8080)]),
        &server,
    );
}
