use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::*;
use crate::validation::test_support::{namespace, service, service_value};

fn request_with(value: Value) -> Result<ServiceRequest> {
    service_request(&serde_json::from_value(value).unwrap(), &namespace())
}

#[test]
fn service_defaults_are_explicit_and_namespace_opt_in_is_exact() {
    let request = service_request(&service(), &namespace()).unwrap();

    assert_eq!(request.replicas, 1);
    assert_eq!(request.ports[0].proxy_protocol, ProxyProtocol::None);

    for label in [None, Some("false"), Some("True"), Some("1"), Some("true ")] {
        let mut ns = namespace();
        ns.metadata.labels = label.map(|v| BTreeMap::from([(ENABLED_LABEL.into(), v.into())]));

        assert!(service_request(&service(), &ns).is_err());
    }

    let mut ns = namespace();
    ns.metadata.name = Some("other".into());

    assert!(service_request(&service(), &ns).is_err());
}

#[test]
fn node_ports_do_not_change_tunnel_destination_or_public_ports() {
    let expected = service_request(&service(), &namespace()).unwrap();

    for allocation in [None, Some(true), Some(false)] {
        for node_port in [None, Some(30080)] {
            let mut s = service();
            let spec = s.spec.as_mut().unwrap();
            spec.allocate_load_balancer_node_ports = allocation;
            spec.ports.as_mut().unwrap()[0].node_port = node_port;

            assert_eq!(
                service_request(&s, &namespace()).unwrap(),
                expected,
                "allocation={allocation:?}, node_port={node_port:?}"
            );
        }
    }
}

#[test]
fn services_reject_implicit_or_unsupported_exposure() {
    for (field, value) in [
        ("type", json!("ClusterIP")),
        ("type", json!("ExternalName")),
        ("loadBalancerClass", Value::Null),
        ("loadBalancerClass", json!("other")),
        ("selector", json!({})),
        ("selector", Value::Null),
        ("clusterIP", json!("None")),
        ("clusterIP", json!("::1")),
        ("clusterIP", json!("127.0.0.1")),
        ("externalIPs", json!(["1.2.3.4"])),
        ("externalName", json!("external.example")),
        ("healthCheckNodePort", json!(32000)),
        ("publishNotReadyAddresses", json!(true)),
        ("internalTrafficPolicy", json!("Local")),
        ("externalTrafficPolicy", json!("Local")),
        ("loadBalancerSourceRanges", json!(["10.0.0.0/8"])),
        ("loadBalancerIP", json!("1.2.3.4")),
        ("ipFamilies", json!(["IPv4", "IPv6"])),
        ("clusterIPs", json!(["10.96.0.10", "::1"])),
        ("ipFamilyPolicy", json!("mystery")),
    ] {
        let mut v = service_value();
        v["spec"][field] = value;
        let error = request_with(v).unwrap_err();

        assert!(
            matches!(
                error.downcast_ref::<ValidationError>(),
                Some(ValidationError::InvalidService(_))
            ),
            "{field}: {error}"
        );
    }
}

#[test]
fn service_ports_reject_bad_ranges_protocols_and_ambiguous_names() {
    for (field, value) in [
        ("port", json!(0)),
        ("port", json!(-1)),
        ("port", json!(65536)),
        ("targetPort", json!(0)),
        ("targetPort", json!(65536)),
        ("targetPort", json!("80")),
        ("targetPort", json!("bad/name")),
        ("targetPort", json!("foo--bar")),
        ("protocol", json!("SCTP")),
        ("protocol", json!("tcp")),
        ("protocol", json!("")),
        ("name", json!("bad/name")),
    ] {
        let mut v = service_value();
        v["spec"]["ports"][0][field] = value;

        assert!(request_with(v).is_err(), "{field}");
    }

    for ports in [
        json!([]),
        json!([{"name":"a","port":80}, {"name":"a","port":81}]),
        json!([{"name":"a","port":80}, {"name":"b","port":80}]),
        json!([{"port":80}, {"name":"b","port":81}]),
    ] {
        let mut v = service_value();
        v["spec"]["ports"] = ports;

        assert!(request_with(v).is_err());
    }
}

#[test]
fn valid_selection_annotations_and_proxy_protocol_are_typed() {
    let mut v = service_value();
    v["metadata"]["annotations"] =
        json!({SERVERS:"edge-a, edge-b", REPLICAS:"2", PROXY_PROTOCOL:"http=v1"});
    let request = request_with(v).unwrap();

    assert_eq!(request.servers, vec!["edge-a", "edge-b"]);
    assert_eq!(request.replicas, 2);
    assert_eq!(request.ports[0].proxy_protocol, ProxyProtocol::V1);

    let mut v = service_value();
    v["metadata"]["annotations"] =
        json!({POOL:"west", REPLICAS:"3", PROXY_PROTOCOL:"http=none", "other.io/value":"anything"});
    let request = request_with(v).unwrap();

    assert_eq!(request.pool.as_deref(), Some("west"));
    assert_eq!(request.replicas, 3);
    assert_eq!(request.ports[0].proxy_protocol, ProxyProtocol::None);
}

#[test]
fn explicit_server_list_implies_replicas_and_rejects_selection_ambiguity() {
    let mut v = service_value();
    v["metadata"]["annotations"] = json!({SERVERS: "one,two"});

    assert_eq!(request_with(v.clone()).unwrap().replicas, 2);

    for extra in [json!({POOL: "west"}), json!({REPLICAS: "1"})] {
        let mut invalid = v.clone();
        invalid["metadata"]["annotations"]
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());

        assert!(request_with(invalid).is_err());
    }
}

#[test]
fn malformed_annotations_never_fall_back_to_defaults() {
    for (key, values) in [
        (
            SERVERS,
            vec![
                "",
                " ",
                "one,one",
                ",one",
                "one,",
                "one,,two",
                "one/other",
                "UPPER",
            ],
        ),
        (POOL, vec!["", "a,b", " west", "west/", "Upper"]),
        (
            REPLICAS,
            vec!["", "0", "-1", "+1", "01", "1.0", "1 ", "65536", "all"],
        ),
        (
            PROXY_PROTOCOL,
            vec![
                "",
                "http",
                "http=",
                "=v1",
                "http=true",
                "http=V1",
                "http=v1,",
                "http=v1,http=v2",
                "other=v2",
                "http=v1=v2",
                "http =v1",
            ],
        ),
    ] {
        for value in values {
            let mut v = service_value();
            v["metadata"]["annotations"] = json!({key: value});
            let result = request_with(v);

            assert!(result.is_err(), "{key}={value:?}");
        }
    }
}

#[test]
fn udp_rejects_proxy_v1_but_accepts_v2_and_none() {
    for (mode, valid) in [("v1", false), ("v2", true), ("none", true)] {
        let mut v = service_value();
        v["spec"]["ports"][0]["protocol"] = json!("UDP");
        v["metadata"]["annotations"] = json!({PROXY_PROTOCOL: format!("http={mode}")});

        assert_eq!(request_with(v).is_ok(), valid);
    }
}
