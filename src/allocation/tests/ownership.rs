use super::*;

#[test]
fn idempotent_retries_preserve_control_even_when_a_lower_port_is_free() {
    let machine = machine();
    let mut ledger = Ledger::default();
    let a = service("a", &[(Protocol::Tcp, 443)]);
    let b = service("b", &[(Protocol::Tcp, 8080), (Protocol::Udp, 53)]);
    ledger.allocate("a", &a, &machine).unwrap();
    assert_eq!(ledger.allocate("b", &b, &machine).unwrap(), 20001);
    ledger.release("a");
    let before = ledger.clone();
    assert_eq!(ledger.allocate("b", &b, &machine).unwrap(), 20001);
    assert_eq!(ledger, before);
    let mut updated = b;
    updated.ports.reverse();
    updated.ports[0].name = "renamed".into();
    updated.ports[0].proxy_protocol = ProxyProtocol::V2;
    updated.cluster_ip = "10.96.1.20".parse().unwrap();
    updated.selector = BTreeMap::from([("app".into(), "new-backend".into())]);
    updated.machines.clear();
    updated.pool = Some("pool".into());
    updated.replicas = 3;
    assert_eq!(ledger.allocate("b", &updated, &machine).unwrap(), 20001);
    assert_eq!(ledger, before);
}

#[test]
fn publication_id_cannot_be_reassigned_to_another_owner_or_reservation_set() {
    let machine = machine();
    let original = service("a", &[(Protocol::Tcp, 443)]);
    let mut ledger = Ledger::default();
    ledger.allocate("p", &original, &machine).unwrap();
    let mut changes = vec![original.clone(); 6];
    changes[0].uid = "new-service-uid".into();
    changes[1].name = "renamed-service".into();
    changes[2].namespace = "another-namespace".into();
    changes[3].ports[0].port = 8443;
    changes[4].ports[0].protocol = Protocol::Udp;
    changes[5]
        .ports
        .push(service("unused", &[(Protocol::Udp, 53)]).ports.remove(0));

    for changed in changes {
        assert_rejected(&mut ledger, "p", &changed, &machine);
    }

    assert_rejected(&mut ledger, "other-id", &original, &machine);
}

#[test]
fn publication_id_cannot_move_to_another_machine_identity_or_address() {
    let original = machine();
    let service = service("a", &[(Protocol::Tcp, 443)]);
    let mut ledger = Ledger::default();
    ledger.allocate("p", &service, &original).unwrap();
    let mut changes = vec![original.clone(); 3];
    changes[0].metadata.uid = Some("new-machine-uid".into());
    changes[1].metadata.name = Some("another-machine-name".into());
    changes[2].spec.address = "203.0.113.11".into();

    for changed in changes {
        assert_rejected(&mut ledger, "p", &service, &changed);
    }
}

#[test]
fn address_aliases_and_recreated_machine_objects_share_collision_scope() {
    let original = machine();
    let mut ledger = Ledger::default();
    ledger
        .allocate("a", &service("a", &[(Protocol::Tcp, 443)]), &original)
        .unwrap();
    let mut alias = original.clone();
    alias.metadata.name = Some("edge-alias".into());
    alias.metadata.uid = Some("alias-uid".into());
    let conflicting = service("b", &[(Protocol::Udp, 443)]);
    assert_rejected(&mut ledger, "alias", &conflicting, &alias);
    assert_rejected(
        &mut ledger,
        "alias",
        &service("b", &[(Protocol::Tcp, 20000)]),
        &alias,
    );
    assert_rejected(
        &mut ledger,
        "alias",
        &service("b", &[(Protocol::Udp, 20000)]),
        &alias,
    );
    assert_eq!(
        ledger
            .allocate("alias", &service("b", &[(Protocol::Udp, 8080)]), &alias)
            .unwrap(),
        20001
    );

    let mut recreated = original.clone();
    recreated.metadata.uid = Some("recreated-uid".into());
    assert_rejected(&mut ledger, "recreated", &conflicting, &recreated);
    recreated.spec.address = "203.0.113.99".into();
    assert_rejected(&mut ledger, "recreated", &conflicting, &recreated);

    let mut renamed = original;
    renamed.metadata.name = Some("renamed".into());
    renamed.spec.address = "203.0.113.98".into();
    assert_rejected(&mut ledger, "renamed", &conflicting, &renamed);
}

#[test]
fn independent_machines_can_reuse_public_and_control_ports() {
    let first = machine();
    let mut other = machine();
    other.metadata.name = Some("other-machine".into());
    other.metadata.uid = Some("other-uid".into());
    other.spec.address = "203.0.113.11".into();
    let service = service("a", &[(Protocol::Tcp, 443)]);
    let mut ledger = Ledger::default();
    assert_eq!(ledger.allocate("a", &service, &first).unwrap(), 20000);
    assert_eq!(ledger.allocate("b", &service, &other).unwrap(), 20000);
}

#[test]
fn aliases_cannot_bypass_each_others_ssh_or_administrator_exclusions() {
    let mut original = machine();
    original.spec.ssh.port = 2222;
    original.spec.reserved_ports = vec![8443, 20001];
    let mut alias = machine();
    alias.metadata.name = Some("alias".into());
    alias.metadata.uid = Some("alias-uid".into());
    let mut ledger = Ledger::default();
    ledger
        .allocate("a", &service("a", &[(Protocol::Tcp, 443)]), &original)
        .unwrap();

    for protocol in [Protocol::Tcp, Protocol::Udp] {
        for port in [2222, 8443, 20001] {
            assert_rejected(
                &mut ledger,
                "alias",
                &service("b", &[(protocol, port)]),
                &alias,
            );
        }
    }

    assert_eq!(
        ledger
            .allocate("alias", &service("b", &[(Protocol::Tcp, 8080)]), &alias)
            .unwrap(),
        20002
    );
}

#[test]
fn policy_changes_cannot_silently_replace_an_existing_control_port() {
    let original = machine();
    let service = service("a", &[(Protocol::Tcp, 443)]);
    let mut ledger = Ledger::default();
    ledger.allocate("p", &service, &original).unwrap();
    let mut changes = vec![original.clone(); 4];
    changes[0].spec.control_port_range.start = 20001;
    changes[1].spec.reserved_ports.push(20000);
    changes[2].spec.ssh.port = 20000;
    changes[3].spec.reserved_ports.push(443);

    for changed in changes {
        let error = assert_rejected(&mut ledger, "p", &service, &changed);

        if changed.spec.control_port_range.start == 20001 {
            assert!(error.downcast_ref::<AllocationConflict>().is_none());
        }
    }

    let mut compatible = original;
    compatible.spec.reserved_ports.push(8443);
    assert_eq!(ledger.allocate("p", &service, &compatible).unwrap(), 20000);
    assert_eq!(
        ledger.allocations["p"].reserved_ports,
        BTreeSet::from([22, 8443])
    );
}

#[test]
fn invalid_machine_identity_address_or_port_policy_is_rejected() {
    let original = machine();
    let service = service("a", &[(Protocol::Tcp, 443)]);
    let mut ledger = Ledger::default();
    let mut changes = vec![original; 11];
    changes[0].metadata.name = None;
    changes[1].metadata.name = Some(String::new());
    changes[2].metadata.uid = None;
    changes[3].metadata.uid = Some(String::new());
    changes[4].spec.address = "example.com".into();
    changes[5].spec.address = "::1".into();
    changes[6].spec.ssh.port = 0;
    changes[7].spec.reserved_ports.push(0);
    changes[8].spec.control_port_range.start = 0;
    changes[9].spec.control_port_range = PortRange {
        start: 20001,
        end: 20000,
    };
    changes[10].spec.control_port_range.end = 0;

    for changed in changes {
        assert_rejected(&mut ledger, "p", &service, &changed);
    }
}
