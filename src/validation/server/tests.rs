use serde_json::json;

use super::*;

fn server() -> Server {
    serde_json::from_value(json!({
        "apiVersion": "tunnellb.io/v1alpha1", "kind": "Server",
        "metadata": {"name": "edge", "uid": "server-uid"},
        "spec": {
            "address": "8.8.8.8",
            "ssh": {"user": "deploy", "privateKeySecretRef": {"name": "edge-key"}},
            "controlPortRange": {"start": 20000, "end": 20002}
        }
    }))
    .unwrap()
}

#[test]
fn server_requires_public_ipv4_unless_private_test_mode_is_explicit() {
    let mut m = server();

    assert_eq!(
        validate_server(&m, &[], false).unwrap(),
        Ipv4Addr::new(8, 8, 8, 8)
    );

    for ip in ["10.1.2.3", "172.16.0.2", "172.31.255.1", "192.168.8.2"] {
        m.spec.address = ip.into();

        assert!(validate_server(&m, &[], false).is_err(), "{ip}");
        assert!(validate_server(&m, &[], true).is_ok(), "{ip}");
    }

    for ip in ["172.15.0.2", "172.32.0.2", "192.169.8.2"] {
        m.spec.address = ip.into();

        assert!(validate_server(&m, &[], false).is_ok(), "{ip}");
    }
}

#[test]
fn private_mode_never_admits_nonunicast_or_reserved_addresses() {
    let mut m = server();

    for ip in [
        "localhost",
        "::1",
        "::ffff:8.8.8.8",
        "8.8.8.8:22",
        "8.8.8.8/32",
        "8.08.8.8",
        " 8.8.8.8",
        "0.0.0.0",
        "0.1.2.3",
        "127.0.0.2",
        "169.254.169.254",
        "100.64.0.1",
        "100.127.255.254",
        "192.0.0.8",
        "192.0.2.1",
        "192.88.99.1",
        "198.18.0.1",
        "198.19.1.1",
        "198.51.100.5",
        "203.0.113.5",
        "224.0.0.1",
        "239.255.255.254",
        "240.0.0.1",
        "255.255.255.255",
    ] {
        m.spec.address = ip.into();

        for allow_private in [false, true] {
            let error = validate_server(&m, &[], allow_private).unwrap_err();

            assert!(
                matches!(
                    error.downcast_ref::<ValidationError>(),
                    Some(ValidationError::InvalidServer(_))
                ),
                "{ip}: {error}"
            );
        }
    }
}

#[test]
fn node_address_exclusion_applies_even_in_private_mode_and_to_mapped_ipv4() {
    for (address, node_address) in [
        ("8.8.8.8", "8.8.8.8"),
        ("10.1.2.3", "10.1.2.3"),
        ("10.1.2.3", "::ffff:10.1.2.3"),
    ] {
        for address_type in ["InternalIP", "ExternalIP"] {
            let mut m = server();
            m.spec.address = address.into();
            let node: Node = serde_json::from_value(json!({
                "metadata": {"name": "worker"},
                "status": {"addresses": [{"type": address_type, "address": node_address}]}
            }))
            .unwrap();

            for allow_private in [false, true] {
                let error =
                    validate_server(&m, std::slice::from_ref(&node), allow_private).unwrap_err();

                assert!(
                    error
                        .to_string()
                        .contains("belongs to Kubernetes Node worker"),
                    "{error}"
                );
            }
        }
    }
}

#[test]
fn ssh_username_and_secret_reference_reject_injection() {
    for user in [
        "",
        "-oProxyCommand=x",
        "root;id",
        "root\nid",
        "$(id)",
        "root@host",
        "a b",
        "../root",
        "1root",
        "déploy",
    ] {
        let mut m = server();
        m.spec.ssh.user = user.into();

        assert!(validate_server(&m, &[], false).is_err(), "{user:?}");
    }

    for user in ["root", "deploy_1", "_worker", "Deploy-user"] {
        let mut m = server();
        m.spec.ssh.user = user.into();

        assert!(validate_server(&m, &[], false).is_ok(), "{user:?}");
    }

    for name in ["", "bad/name", "-key", "UpperCase", "a..b", "../key"] {
        let mut m = server();
        m.spec.ssh.private_key_secret_ref.name = name.into();

        assert!(validate_server(&m, &[], false).is_err(), "{name:?}");
    }

    for key in [
        "", ".", "..", "../key", "..data", "key/path", "key\n", "$(id)",
    ] {
        let mut m = server();
        m.spec.ssh.private_key_secret_ref.key = key.into();

        assert!(validate_server(&m, &[], false).is_err(), "{key:?}");
    }
}

#[test]
fn server_control_range_and_reservations_are_checked() {
    for (start, end, reserved, ssh) in [
        (0, 3, vec![], 22),
        (30, 20, vec![], 22),
        (22, 22, vec![], 22),
        (20, 22, vec![20, 21], 22),
        (20, 30, vec![0], 22),
        (20, 30, vec![23, 23], 22),
        (20, 30, vec![], 0),
    ] {
        let mut m = server();
        m.spec.control_port_range = crate::api::PortRange { start, end };
        m.spec.reserved_ports = reserved;
        m.spec.ssh.port = ssh;

        assert!(validate_server(&m, &[], false).is_err());
    }

    let mut m = server();
    m.spec.control_port_range = crate::api::PortRange {
        start: 65535,
        end: 65535,
    };

    assert!(validate_server(&m, &[], false).is_ok());
}
