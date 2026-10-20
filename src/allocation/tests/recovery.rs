use super::*;

#[test]
fn validation_and_identity_errors_cannot_be_hidden_by_early_port_collisions() {
    for problem in ["address", "duplicate", "zero", "identity", "stored"] {
        let mut server = server();
        let mut ledger = Ledger::default();
        ledger
            .allocate("a", &service("a", &[(Protocol::Tcp, 443)]), &server)
            .unwrap();
        let mut request = service("b", &[(Protocol::Tcp, 22)]);
        let mut id = "b";
        match problem {
            "address" => server.spec.address = "not-an-ip".into(),
            "duplicate" => request.ports.push(request.ports[0].clone()),
            "zero" => request
                .ports
                .push(service("b", &[(Protocol::Tcp, 0)]).ports.remove(0)),
            "identity" => id = "a",
            _ => ledger.allocations.get_mut("a").unwrap().control_port = 0,
        }

        let before = ledger.clone();
        let error = ledger.allocate(id, &request, &server).unwrap_err();
        assert!(
            error.downcast_ref::<AllocationConflict>().is_none(),
            "{problem}: {error}"
        );
        assert_eq!(ledger, before);
    }
}

#[test]
fn later_corruption_and_overlapping_stored_leases_are_not_availability_failures() {
    let server = server();
    let mut ledger = Ledger::default();
    ledger
        .allocate("a", &service("a", &[(Protocol::Tcp, 443)]), &server)
        .unwrap();
    ledger
        .allocate("z", &service("z", &[(Protocol::Tcp, 8443)]), &server)
        .unwrap();

    for overlap in [false, true] {
        let mut corrupt = ledger.clone();
        let last = corrupt.allocations.get_mut("z").unwrap();

        if overlap {
            last.ports = BTreeSet::from([PortReservation {
                protocol: Protocol::Udp,
                port: 443,
            }]);
        } else {
            last.control_port = 0;
        }

        let before = corrupt.clone();
        let error = corrupt
            .allocate("b", &service("b", &[(Protocol::Tcp, 443)]), &server)
            .unwrap_err();
        assert!(error.downcast_ref::<AllocationConflict>().is_none());
        assert_eq!(corrupt, before);
    }
}

#[test]
fn unpublished_replacement_is_atomic_and_preserves_ownership() {
    let server = server();
    let original = service("a", &[(Protocol::Tcp, 443)]);
    let mut ledger = Ledger::default();
    ledger.allocate("a", &original, &server).unwrap();
    ledger
        .allocate("b", &service("b", &[(Protocol::Tcp, 8443)]), &server)
        .unwrap();

    for problem in ["collision", "owner", "server", "corrupt"] {
        let mut candidate = ledger.clone();
        let mut request = service("a", &[(Protocol::Udp, 9443)]);
        let mut target = server.clone();
        match problem {
            "collision" => request.ports[0].port = 8443,
            "owner" => request.uid = "replacement-service".into(),
            "server" => target.metadata.uid = Some("replacement-server".into()),
            _ => candidate.allocations.get_mut("a").unwrap().control_port = 0,
        }

        let before = candidate.clone();
        let error = candidate
            .allocate_unpublished("a", &request, &target)
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<AllocationConflict>().is_some(),
            problem == "collision"
        );
        assert_eq!(candidate, before);
    }

    let mut request = original;
    request.ports[0].port = 9443;
    let mut changed_address = server;
    changed_address.spec.address = "203.0.113.11".into();
    assert_eq!(
        ledger
            .allocate_unpublished("a", &request, &changed_address)
            .unwrap(),
        20000
    );
    assert_eq!(
        ledger.allocations["a"].server_address.to_string(),
        "203.0.113.11"
    );
    assert!(ledger.allocations.contains_key("b"));
}

#[test]
fn restored_leases_keep_exact_protocol_ownership_and_existing_control() {
    let server = server();

    for protocols in [
        vec![Protocol::Tcp],
        vec![Protocol::Udp],
        vec![Protocol::Tcp, Protocol::Udp],
    ] {
        let ports: Vec<_> = protocols.iter().map(|&protocol| (protocol, 443)).collect();
        let original = service("a", &ports);
        let mut ledger = Ledger::default();
        ledger
            .allocate(
                "filler",
                &service("filler", &[(Protocol::Tcp, 8080)]),
                &server,
            )
            .unwrap();
        assert_eq!(ledger.allocate("a", &original, &server).unwrap(), 20001);
        ledger.release("filler");
        let encoded = serde_json::to_string(&ledger).unwrap();
        let mut restored: Ledger = serde_json::from_str(&encoded).unwrap();
        assert_eq!(restored.allocate("a", &original, &server).unwrap(), 20001);
        assert_eq!(restored, ledger);

        if protocols.len() == 1 {
            let expanded = service("a", &[(Protocol::Tcp, 443), (Protocol::Udp, 443)]);
            assert_rejected(&mut restored, "a", &expanded, &server);
        }

        for protocol in [Protocol::Tcp, Protocol::Udp] {
            assert_rejected(
                &mut restored,
                "other",
                &service("other", &[(protocol, 443)]),
                &server,
            );
        }
    }
}

#[test]
fn serialized_cross_protocol_overlaps_are_not_grandfathered_on_retry() {
    let server = server();
    let a = service("a", &[(Protocol::Tcp, 443)]);
    let mut ledger = Ledger::default();
    ledger.allocate("a", &a, &server).unwrap();
    ledger
        .allocate("b", &service("b", &[(Protocol::Udp, 8443)]), &server)
        .unwrap();
    // These states were possible under the old protocol-specific rules:
    // b's UDP public port overlaps either a's public TCP or TCP control.
    for port in [443, 20000] {
        let mut value = serde_json::to_value(&ledger).unwrap();
        value["allocations"]["b"]["ports"][0]["port"] = port.into();
        let mut restored: Ledger = serde_json::from_value(value).unwrap();
        let b = service("b", &[(Protocol::Udp, port)]);
        assert_rejected(&mut restored, "a", &a, &server);
        assert_rejected(&mut restored, "b", &b, &server);
        // Explicit release after revocation permits the remaining lease,
        // without stealing or silently changing its existing control port.
        restored.release("a");
        assert_eq!(restored.allocate("b", &b, &server).unwrap(), 20001);
    }
}

#[test]
fn serialized_own_udp_control_overlap_requires_explicit_release() {
    let server = server();
    let service = service("a", &[(Protocol::Udp, 20000)]);
    let mut ledger = Ledger::default();
    assert_eq!(ledger.allocate("a", &service, &server).unwrap(), 20001);
    let mut value = serde_json::to_value(&ledger).unwrap();
    value["allocations"]["a"]["controlPort"] = 20000.into();
    let mut restored: Ledger = serde_json::from_value(value).unwrap();
    assert_rejected(&mut restored, "a", &service, &server);
    restored.release("a");
    assert_eq!(restored.allocate("a", &service, &server).unwrap(), 20001);
}

#[test]
fn invalid_stored_reservations_are_not_treated_as_available() {
    let server = server();
    let service = service("a", &[(Protocol::Tcp, 443)]);
    let mut ledger = Ledger::default();
    ledger.allocate("p", &service, &server).unwrap();
    let mut value = serde_json::to_value(&ledger).unwrap();
    value["allocations"]["p"]["controlPort"] = 0.into();
    let mut restored: Ledger = serde_json::from_value(value).unwrap();
    assert_rejected(&mut restored, "p", &service, &server);
    assert_rejected(
        &mut restored,
        "q",
        &self::service("b", &[(Protocol::Tcp, 8080)]),
        &server,
    );
}
