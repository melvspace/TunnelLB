use super::*;

#[test]
fn guard_is_exact_stable_and_does_not_exempt_existing_connections() {
    let mut config = GuardConfig {
        allowed: [
            ("203.0.113.12", 20001, Protocol::Tcp),
            ("10.43.0.4", 443, Protocol::Tcp),
            ("10.43.0.4", 53, Protocol::Udp),
        ]
        .into_iter()
        .map(|(address, port, protocol)| AllowedDestination {
            address: address.parse().unwrap(),
            port,
            protocol,
        })
        .collect(),
    };
    let rules = config.ipv4_rules().unwrap();
    assert!(rules.contains("-d 203.0.113.12/32 -p tcp --dport 20001 -j ACCEPT"));
    assert!(rules.contains("-d 10.43.0.4/32 -p udp --dport 53 -j ACCEPT"));
    assert_eq!(rules.matches("-j ACCEPT").count(), 3);
    assert!(!rules.contains("ESTABLISHED"));
    assert!(!rules.contains("RELATED"));
    assert!(!rules.contains("-F OUTPUT"));
    assert!(
        rules.ends_with("-A TUNNELLB_EGRESS -j DROP\n-I OUTPUT 1 -j TUNNELLB_EGRESS\nCOMMIT\n")
    );
    assert!(!config.ipv6_rules().unwrap().contains("ACCEPT"));

    config.allowed.reverse();
    config.allowed.push(config.allowed[0].clone());
    assert_eq!(rules, config.ipv4_rules().unwrap());
}

#[test]
fn guard_rejects_invalid_and_injected_configuration() {
    let mut config = GuardConfig::for_ssh("203.0.113.12:22".parse().unwrap());

    for address in [
        "0.0.0.0",
        "0.1.2.3",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "255.255.255.255",
    ] {
        config.allowed[0].address = address.parse().unwrap();
        assert!(config.validate().is_err(), "{address}");
    }

    config.allowed[0].address = "203.0.113.12".parse().unwrap();
    config.allowed[0].port = 0;
    assert!(config.ipv4_rules().is_err());

    for payload in [
        r#"{"allowed":[{"address":"1.2.3.4\n-A OUTPUT -j ACCEPT","port":22,"protocol":"TCP"}]}"#,
        r#"{"allowed":[{"address":"1.2.3.4/0","port":22,"protocol":"TCP"}]}"#,
        r#"{"allowed":[{"address":"1.2.3.4","port":22,"protocol":"TCP;true"}]}"#,
        r#"{"allowed":[{"address":"1.2.3.4","port":22,"protocol":"TCP","shell":"true"}]}"#,
        r#"{"allowed":[],"allowAll":true}"#,
    ] {
        assert!(serde_json::from_str::<GuardConfig>(payload).is_err());
    }

    assert!(GuardConfig { allowed: vec![] }.validate().is_err());
}

#[test]
fn ssh_guard_has_one_tcp_destination() {
    let config = GuardConfig::for_ssh("203.0.113.20:2222".parse().unwrap());
    let rules = config.ipv4_rules().unwrap();
    assert_eq!(rules.matches("-j ACCEPT").count(), 1);
    assert!(rules.contains("-d 203.0.113.20/32 -p tcp --dport 2222"));
}
