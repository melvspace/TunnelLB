use super::*;
use crate::api::{PublishedPort, ServiceRequest};

fn publication() -> Publication {
    Publication {
        id: "pub-0123456789abcdef".into(),
        server_name: "edge".into(),
        server_uid: "c4a082c0-06f0-4b14-bf90-f5d975cbbf92".into(),
        server_address: "203.0.113.10".parse().unwrap(),
        control_port: 23456,
        service: ServiceRequest {
            namespace: "apps".into(),
            name: "example".into(),
            uid: "service-uid".into(),
            cluster_ip: "10.96.1.10".parse().unwrap(),
            selector: Default::default(),
            ports: vec![
                PublishedPort {
                    name: "https".into(),
                    port: 443,
                    protocol: Protocol::Tcp,
                    proxy_protocol: ProxyProtocol::None,
                },
                PublishedPort {
                    name: "dns".into(),
                    port: 53,
                    protocol: Protocol::Udp,
                    proxy_protocol: ProxyProtocol::None,
                },
            ],
            servers: vec!["edge".into()],
            pool: None,
            replicas: 1,
        },
    }
}

fn config_credentials() -> Credentials {
    Credentials {
        token: "01".repeat(32),
        certificate_pem: "certificate-is-not-embedded-in-config".into(),
        private_key_pem: "private-key-is-not-embedded-in-config".into(),
    }
}

fn parse(config: &str) -> Value {
    toml::from_str(config).unwrap()
}

#[test]
fn credentials_are_independent_and_serializable() {
    let publication = publication();
    let first = credentials(&publication).unwrap();
    let second = credentials(&publication).unwrap();

    assert_eq!(hex::decode(&first.token).unwrap().len(), 32);
    assert_ne!(first.token, second.token);
    assert_ne!(first.certificate_pem, second.certificate_pem);
    assert_ne!(first.private_key_pem, second.private_key_pem);
    assert!(
        first
            .certificate_pem
            .starts_with("-----BEGIN CERTIFICATE-----")
    );
    rcgen::KeyPair::from_pem(&first.private_key_pem).unwrap();

    let restored: Credentials =
        serde_json::from_str(&serde_json::to_string(&first).unwrap()).unwrap();

    assert_eq!(restored.token, first.token);
    assert_eq!(restored.certificate_pem, first.certificate_pem);
    assert_eq!(restored.private_key_pem, first.private_key_pem);
}

#[test]
fn server_forces_tls_at_owned_paths_and_limits_public_ports() {
    let mut publication = publication();
    let mut duplicate_number = publication.service.ports[1].clone();
    duplicate_number.protocol = Protocol::Tcp;
    publication.service.ports.push(duplicate_number);
    let config = parse(&server_config(&publication, &config_credentials()).unwrap());

    assert_eq!(config["maxPortsPerClient"], 3);
    assert_eq!(
        config["allowPorts"],
        json!([{ "single": 53 }, { "single": 443 }])
    );

    let tls = &config["transport"]["tls"];
    assert_eq!(tls["force"], true);
    let directory = format!(
        "/var/lib/tunnellb/{}/publications/{}",
        publication.server_uid, publication.id
    );
    assert_eq!(tls["certFile"], format!("{directory}/tls.crt"));
    assert_eq!(tls["keyFile"], format!("{directory}/tls.key"));
    // Setting this server-side would accidentally require client certificates.
    assert!(tls.get("trustedCaFile").is_none());
}

#[test]
fn client_pins_server_and_only_configures_numeric_service_destinations() {
    let publication = publication();
    let credentials = config_credentials();
    let text = client_config(&publication, &credentials).unwrap();
    let config = parse(&text);
    let tls = &config["transport"]["tls"];

    assert_eq!(tls["enable"], true);
    assert_eq!(tls["trustedCaFile"], "/etc/tunnellb/ca.crt");
    assert_eq!(tls["serverName"], "203.0.113.10");
    assert!(tls.get("certFile").is_none());
    assert!(tls.get("keyFile").is_none());
    assert!(!text.contains(&credentials.private_key_pem));
    assert!(!text.contains(&credentials.certificate_pem));

    let proxies = config["proxies"].as_array().unwrap();
    assert_eq!(proxies.len(), 2);

    for (proxy, protocol, port) in [(&proxies[0], "tcp", 443), (&proxies[1], "udp", 53)] {
        assert_eq!(
            proxy["name"],
            format!("{}-{protocol}-{port}", publication.id)
        );
        assert_eq!(proxy["type"], protocol);
        assert_eq!(proxy["localIP"], "10.96.1.10");
        assert_eq!(proxy["localPort"], port);
        assert_eq!(proxy["remotePort"], port);
        assert!(proxy.get("transport").is_none());
    }
}

#[test]
fn authentication_covers_control_and_work_connections_without_extra_listeners() {
    let publication = publication();
    let credentials = config_credentials();

    for config in [
        server_config(&publication, &credentials).unwrap(),
        client_config(&publication, &credentials).unwrap(),
    ] {
        let config = parse(&config);

        assert_eq!(config["auth"]["method"], "token");
        assert_eq!(config["auth"]["token"], credentials.token);
        assert_eq!(
            config["auth"]["additionalScopes"],
            json!(["HeartBeats", "NewWorkConns"])
        );

        for prohibited in [
            "webServer",
            "httpPlugins",
            "visitors",
            "includes",
            "user",
            "sshTunnelGateway",
            "kcpBindPort",
            "quicBindPort",
            "vhostHTTPPort",
            "vhostHTTPSPort",
        ] {
            assert!(config.get(prohibited).is_none(), "{prohibited}");
        }

        if let Some(proxies) = config.get("proxies") {
            for proxy in proxies.as_array().unwrap() {
                assert!(proxy.get("plugin").is_none());
            }
        }
    }
}

#[test]
fn optional_proxy_protocol_supports_tcp_v1_v2_and_udp_v2() {
    let credentials = config_credentials();

    for (protocol, version, expected) in [
        (Protocol::Tcp, ProxyProtocol::V1, "v1"),
        (Protocol::Tcp, ProxyProtocol::V2, "v2"),
        (Protocol::Udp, ProxyProtocol::V2, "v2"),
    ] {
        let mut publication = publication();
        publication.service.ports.truncate(1);
        publication.service.ports[0].protocol = protocol;
        publication.service.ports[0].proxy_protocol = version;
        let config = parse(&client_config(&publication, &credentials).unwrap());
        let proxy = &config["proxies"][0];

        assert_eq!(proxy["type"], protocol.frp_name());
        assert_eq!(proxy["transport"]["proxyProtocolVersion"], expected);
    }
}

fn assert_invalid(publication: &Publication) {
    assert!(credentials(publication).is_err());
    assert!(server_config(publication, &config_credentials()).is_err());
    assert!(client_config(publication, &config_credentials()).is_err());
}

#[test]
fn rejects_empty_zero_duplicate_control_ports_and_udp_v1() {
    let invalid_cases: [fn(&mut Publication); 6] = [
        |p| p.service.ports.clear(),
        |p| p.control_port = 0,
        |p| p.service.ports[0].port = 0,
        |p| p.service.ports[0].port = p.control_port,
        |p| p.service.ports.push(p.service.ports[0].clone()),
        |p| p.service.ports[1].proxy_protocol = ProxyProtocol::V1,
    ];

    for invalidate in invalid_cases {
        let mut publication = publication();
        invalidate(&mut publication);
        assert_invalid(&publication);
    }
}

#[test]
fn accepts_port_boundaries_and_different_protocols_on_the_same_port() {
    for (control, tcp, udp) in [(u16::MAX, 1, 1), (1, u16::MAX, u16::MAX), (1, u16::MAX, 1)] {
        let mut publication = publication();
        publication.control_port = control;
        publication.service.ports[0].port = tcp;
        publication.service.ports[1].port = udp;

        assert!(server_config(&publication, &config_credentials()).is_ok());
        assert!(client_config(&publication, &config_credentials()).is_ok());
    }
}

#[test]
fn rejects_path_toml_and_go_template_injection() {
    for invalid in [
        "",
        ".",
        "..",
        "../escape",
        "a/b",
        r"a\b",
        "/absolute",
        "has space",
        "a\nb",
        "a\0b",
        r#"x"[[visitors]]"#,
        "{{.Envs.TOKEN}}",
        "é",
        &"a".repeat(64),
    ] {
        let mut publication = publication();
        publication.id = invalid.into();
        assert_invalid(&publication);

        publication = self::publication();
        publication.server_uid = invalid.into();
        assert_invalid(&publication);
    }

    for invalid in [
        "",
        "short",
        "{{.Envs.TOKEN}}",
        "\"\n[webServer]\nport=1234",
        &"z".repeat(64),
    ] {
        let mut credentials = config_credentials();
        credentials.token = invalid.into();

        for result in [
            server_config(&publication(), &credentials),
            client_config(&publication(), &credentials),
        ] {
            let error = result.unwrap_err().to_string();

            assert_eq!(
                error,
                "publication token must be 32 bytes encoded as hexadecimal"
            );
        }
    }
}

#[test]
fn untrusted_metadata_is_never_rendered_and_reordering_is_stable() {
    let mut publication = publication();
    let credentials = config_credentials();
    let original_client = client_config(&publication, &credentials).unwrap();
    let original_server = server_config(&publication, &credentials).unwrap();
    let injection = "\"\n[[visitors]]\n{{.Envs.TOKEN}}";
    publication.server_name = injection.into();
    publication.service.namespace = injection.into();
    publication.service.name = injection.into();
    publication.service.uid = injection.into();
    publication.service.pool = Some(injection.into());
    publication.service.servers = vec![injection.into()];
    publication
        .service
        .selector
        .insert(injection.into(), injection.into());

    for port in &mut publication.service.ports {
        port.name = injection.into();
    }

    publication.service.ports.reverse();
    assert_eq!(
        client_config(&publication, &credentials).unwrap(),
        original_client
    );
    assert_eq!(
        server_config(&publication, &credentials).unwrap(),
        original_server
    );
    assert!(!original_client.contains("{{"));
    assert!(!original_server.contains("{{"));
}
