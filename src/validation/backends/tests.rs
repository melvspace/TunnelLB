use serde_json::{Value, json};

use super::*;
use crate::validation::{
    service_request,
    test_support::{namespace, service, service_value},
};

fn slice_value() -> Value {
    json!({
        "metadata": {
            "name": "web-abc", "namespace": "apps",
            "labels": {
                SLICE_SERVICE: "web", SLICE_MANAGER: "endpointslice-controller.k8s.io"
            },
            "ownerReferences": [{
                "apiVersion": "v1", "kind": "Service", "name": "web",
                "uid": "service-uid", "controller": true
            }]
        },
        "addressType": "IPv4",
        "ports": [{"name": "http", "protocol": "TCP", "port": 8080}],
        "endpoints": [{
            "addresses": ["10.42.0.7"],
            "conditions": {"ready": true, "serving": true, "terminating": false},
            // The built-in controller omits apiVersion on Pod references.
            "targetRef": {"kind": "Pod", "namespace": "apps", "name": "web-0", "uid": "pod-uid"}
        }]
    })
}

fn pod_value() -> Value {
    json!({
        "metadata": {"name": "web-0", "namespace": "apps", "uid": "pod-uid", "labels": {"app": "web"}},
        "spec": {"containers": [{"name": "web", "ports": [{"name": "web", "containerPort": 8080}]}]},
        "status": {
            "phase": "Running", "podIP": "10.42.0.7", "podIPs": [{"ip": "10.42.0.7"}],
            "hostIP": "192.168.1.7", "conditions": [{"type": "Ready", "status": "True"}]
        }
    })
}

fn backend_with(slice: Value, pod: Value) -> Result<Vec<BackendPort>> {
    backend_with_service(service_value(), slice, pod)
}

fn backend_with_service(service: Value, slice: Value, pod: Value) -> Result<Vec<BackendPort>> {
    let service = serde_json::from_value(service).unwrap();
    let request = service_request(&service, &namespace()).unwrap();
    validate_backends(
        &request,
        &service,
        &[serde_json::from_value(slice).unwrap()],
        &[serde_json::from_value(pod).unwrap()],
    )
}

fn assert_unsafe(result: Result<Vec<BackendPort>>, expected: &str) {
    let error = result.unwrap_err();

    assert!(
        matches!(
            error.downcast_ref::<ValidationError>(),
            Some(ValidationError::UnsafeBackend(_))
        ),
        "{error}"
    );

    assert!(
        error.to_string().contains(expected),
        "{error}, expected {expected}"
    );
}

fn assert_unavailable(result: Result<Vec<BackendPort>>, expected: &str) {
    let error = result.unwrap_err();

    assert!(
        error
            .downcast_ref::<ValidationError>()
            .unwrap()
            .is_backend_unavailable(),
        "{error}"
    );

    assert!(
        error.to_string().contains(expected),
        "{error}, expected {expected}"
    );
}

#[test]
fn validates_real_controller_shaped_endpoint_and_deduplicates_ports() {
    let slice: EndpointSlice = serde_json::from_value(slice_value()).unwrap();
    let pod = serde_json::from_value(pod_value()).unwrap();
    let s = service();
    let request = service_request(&s, &namespace()).unwrap();
    let ports = validate_backends(&request, &s, &[slice.clone(), slice], &[pod]).unwrap();

    assert_eq!(
        ports,
        vec![BackendPort {
            protocol: Protocol::Tcp,
            port: 8080
        }]
    );
}

#[test]
fn slice_provenance_namespace_and_ownership_cannot_be_forged() {
    for (pointer, value, reason) in [
        ("/metadata/namespace", json!("other"), "namespace"),
        (
            "/metadata/labels/kubernetes.io~1service-name",
            json!("other"),
            "service-name",
        ),
        (
            "/metadata/labels/endpointslice.kubernetes.io~1managed-by",
            json!("manual"),
            "managed",
        ),
        (
            "/metadata/ownerReferences/0/uid",
            json!("old-service-uid"),
            "exact UID",
        ),
        (
            "/metadata/ownerReferences/0/name",
            json!("other"),
            "exact UID",
        ),
        (
            "/metadata/ownerReferences/0/kind",
            json!("Pod"),
            "exact UID",
        ),
        (
            "/metadata/ownerReferences/0/apiVersion",
            json!("other/v1"),
            "exact UID",
        ),
        (
            "/metadata/ownerReferences/0/controller",
            json!(false),
            "exact UID",
        ),
        ("/metadata/ownerReferences", json!([]), "exact UID"),
        ("/addressType", json!("IPv6"), "IPv4"),
    ] {
        for ready in [true, false] {
            let mut slice = slice_value();
            *slice.pointer_mut(pointer).unwrap() = value.clone();
            slice["endpoints"][0]["conditions"]["ready"] = json!(ready);

            assert_unsafe(backend_with(slice, pod_value()), reason);
        }
    }
}

#[test]
fn hostile_target_references_are_unsafe_even_when_not_ready() {
    for (field, value, reason) in [
        ("kind", json!("Node"), "whole v1 Pod"),
        ("namespace", json!("other"), "namespace"),
        ("uid", Value::Null, "targetRef.uid"),
        ("uid", json!(""), "targetRef.uid"),
        ("name", Value::Null, "targetRef.name"),
        ("name", json!(""), "targetRef.name"),
        ("apiVersion", json!("evil.io/v1"), "whole v1 Pod"),
        ("fieldPath", json!("spec.containers{web}"), "whole v1 Pod"),
    ] {
        let mut slice = slice_value();
        slice["endpoints"][0]["targetRef"][field] = value;
        slice["endpoints"][0]["conditions"]["ready"] = json!(false);

        assert_unsafe(backend_with(slice, pod_value()), reason);
    }

    let mut slice = slice_value();
    slice["endpoints"][0]["targetRef"] = Value::Null;
    slice["endpoints"][0]["conditions"]["ready"] = json!(false);

    assert_unsafe(backend_with(slice, pod_value()), "targetRef");
}

#[test]
fn pod_identity_selector_and_network_must_match() {
    for (pointer, value, reason) in [
        ("/metadata/namespace", json!("other"), "absent"),
        ("/metadata/name", json!("other"), "absent"),
        ("/metadata/uid", json!("other"), "UID"),
        ("/metadata/labels/app", json!("unselected"), "selector"),
        ("/spec", Value::Null, "no spec"),
        ("/status", Value::Null, "no status IP"),
    ] {
        let mut pod = pod_value();
        *pod.pointer_mut(pointer).unwrap() = value;

        assert_unsafe(backend_with(slice_value(), pod), reason);
    }

    let mut pod = pod_value();
    pod["spec"]["hostNetwork"] = json!(true);

    assert_unsafe(backend_with(slice_value(), pod), "hostNetwork");

    for (field, value) in [
        ("hostIP", json!("10.42.0.7")),
        ("hostIPs", json!([{"ip": "::ffff:10.42.0.7"}])),
    ] {
        let mut pod = pod_value();
        pod["status"][field] = value;

        assert_unsafe(backend_with(slice_value(), pod), "host IP");
    }
}

#[test]
fn endpoint_address_must_be_exactly_one_real_pod_ipv4() {
    for (addresses, reason) in [
        (json!([]), "exactly one"),
        (json!(["10.42.0.7", "8.8.8.8"]), "exactly one"),
        (json!(["8.8.8.8"]), "does not equal"),
        (json!(["::ffff:10.42.0.7"]), "ordinary unicast"),
        (json!(["10.42.0.8"]), "does not equal"),
        (json!(["127.0.0.1"]), "ordinary unicast"),
        (json!(["169.254.169.254"]), "ordinary unicast"),
        (json!(["224.0.0.1"]), "ordinary unicast"),
    ] {
        let mut slice = slice_value();
        slice["endpoints"][0]["addresses"] = addresses;

        assert_unsafe(backend_with(slice.clone(), pod_value()), reason);

        if reason != "does not equal" {
            slice["endpoints"][0]["conditions"]["ready"] = json!(false);
            assert_unsafe(backend_with(slice, pod_value()), reason);
        }
    }
}

#[test]
fn shared_address_space_is_allowed_for_pods_and_cluster_ips() {
    let mut s = service_value();
    s["spec"]["clusterIP"] = json!("100.64.0.10");
    s["spec"]["clusterIPs"] = json!(["100.64.0.10"]);
    let mut pod = pod_value();
    pod["status"]["podIP"] = json!("100.65.0.7");
    pod["status"]["podIPs"] = json!([{"ip": "100.65.0.7"}]);
    let mut slice = slice_value();
    slice["endpoints"][0]["addresses"] = json!(["100.65.0.7"]);

    assert!(backend_with_service(s, slice, pod).is_ok());
}

#[test]
fn routable_forged_endpoints_are_not_hidden_by_another_ready_backend() {
    let mut service = service_value();
    service["spec"]["ports"][0]["targetPort"] = json!("web");
    let service = serde_json::from_value(service).unwrap();
    let request = service_request(&service, &namespace()).unwrap();

    for conditions in [
        json!({"ready": true, "serving": false}),
        json!({"serving": false}),
        json!({"ready": false, "terminating": true, "serving": true}),
        json!({"ready": false, "terminating": true}),
    ] {
        for problem in [
            "absent",
            "UID",
            "selector",
            "hostNetwork",
            "host IP",
            "does not equal",
            "resolves to",
        ] {
            let mut slice = slice_value();
            let mut endpoint = slice["endpoints"][0].clone();
            endpoint["conditions"] = conditions.clone();
            endpoint["targetRef"]["name"] = json!("other-web");
            endpoint["targetRef"]["uid"] = json!("other-uid");
            endpoint["addresses"] = json!(["10.42.0.8"]);
            let mut pod = pod_value();
            pod["metadata"]["name"] = json!("other-web");
            pod["metadata"]["uid"] = json!("other-uid");
            pod["status"]["podIP"] = json!("10.42.0.8");
            pod["status"]["podIPs"] = json!([{"ip": "10.42.0.8"}]);

            match problem {
                "UID" => pod["metadata"]["uid"] = json!("recreated"),
                "selector" => pod["metadata"]["labels"]["app"] = json!("other"),
                "hostNetwork" => pod["spec"]["hostNetwork"] = json!(true),
                "host IP" => pod["status"]["hostIP"] = json!("10.42.0.8"),
                "does not equal" => endpoint["addresses"] = json!(["8.8.8.8"]),
                "resolves to" => {
                    pod["spec"]["containers"][0]["ports"][0]["containerPort"] = json!(9090)
                }
                _ => {}
            }

            let mut pods = vec![serde_json::from_value(pod_value()).unwrap()];

            if problem != "absent" {
                pods.push(serde_json::from_value(pod).unwrap());
            }

            slice["endpoints"].as_array_mut().unwrap().push(endpoint);
            let slice = serde_json::from_value(slice).unwrap();
            assert_unsafe(
                validate_backends(&request, &service, &[slice], &pods),
                problem,
            );
        }
    }
}

#[test]
fn no_endpoints_is_unavailable_but_unverifiable_pods_are_unsafe() {
    let s = service();
    let request = service_request(&s, &namespace()).unwrap();

    assert_unavailable(validate_backends(&request, &s, &[], &[]), "no endpoints");
    let slice = serde_json::from_value(slice_value()).unwrap();

    assert_unsafe(validate_backends(&request, &s, &[slice], &[]), "absent");

    let pod: Pod = serde_json::from_value(pod_value()).unwrap();

    assert_unsafe(
        validate_backends(&request, &s, &[], &[pod.clone(), pod]),
        "duplicate Pod object",
    );

    let mut slice = slice_value();
    slice["endpoints"] = json!([]);
    slice["ports"] = json!([]);

    assert_unavailable(backend_with(slice, pod_value()), "no endpoints");
}

#[test]
fn stale_nonroutable_endpoints_do_not_require_current_pods() {
    let mut service = service_value();
    service["spec"]["ports"][0]["targetPort"] = json!("web");
    let service = serde_json::from_value(service).unwrap();
    let request = service_request(&service, &namespace()).unwrap();

    for conditions in [
        json!({"ready": false}),
        json!({"ready": false, "terminating": false, "serving": true}),
        json!({"ready": false, "terminating": true, "serving": false}),
    ] {
        for (missing, deleting) in [(true, false), (true, true), (false, false), (false, true)] {
            let mut stale = slice_value();

            if deleting {
                stale["metadata"]["deletionTimestamp"] = json!("2026-01-01T00:00:00Z");
            }

            stale["endpoints"][0]["conditions"] = conditions.clone();
            stale["endpoints"][0]["targetRef"]["name"] = json!("old-web");
            stale["ports"][0]["port"] = json!(9090);
            let stale = serde_json::from_value(stale).unwrap();
            let mut pods = Vec::new();

            if !missing {
                let mut old_pod = pod_value();
                old_pod["metadata"]["name"] = json!("old-web");
                old_pod["metadata"]["labels"]["app"] = json!("other");
                pods.push(serde_json::from_value(old_pod).unwrap());
            }

            assert_unavailable(
                validate_backends(&request, &service, std::slice::from_ref(&stale), &pods),
                "not ready",
            );

            let ready = serde_json::from_value(slice_value()).unwrap();
            pods.push(serde_json::from_value(pod_value()).unwrap());
            assert_eq!(
                validate_backends(&request, &service, &[stale, ready], &pods).unwrap(),
                vec![BackendPort {
                    protocol: Protocol::Tcp,
                    port: 8080
                }],
            );
        }
    }
}

#[test]
fn readiness_filtering_reports_the_actual_reason() {
    for (field, value, reason) in [
        ("ready", false, "not ready"),
        ("serving", false, "not serving"),
        ("terminating", true, "terminating"),
    ] {
        let mut slice = slice_value();
        slice["endpoints"][0]["conditions"][field] = json!(value);

        assert_unavailable(backend_with(slice, pod_value()), reason);
    }

    for (field, value, reason) in [
        ("phase", json!("Pending"), "not Running"),
        (
            "conditions",
            json!([{"type": "Ready", "status": "False"}]),
            "Ready condition",
        ),
    ] {
        let mut pod = pod_value();
        pod["status"][field] = value;

        assert_unavailable(backend_with(slice_value(), pod), reason);
    }

    let mut pod = pod_value();
    pod["metadata"]["deletionTimestamp"] = json!("2026-01-01T00:00:00Z");

    assert_unavailable(backend_with(slice_value(), pod), "terminating");

    let mut slice = slice_value();
    slice["metadata"]["deletionTimestamp"] = json!("2026-01-01T00:00:00Z");

    assert_unavailable(
        backend_with(slice.clone(), pod_value()),
        "Slice is deleting",
    );

    slice["endpoints"][0]["targetRef"]["uid"] = json!("wrong");

    assert_unsafe(backend_with(slice, pod_value()), "UID");
}

#[test]
fn omitted_conditions_use_kubernetes_defaults_but_require_a_ready_pod() {
    let mut slice = slice_value();
    slice["endpoints"][0]["conditions"] = Value::Null;

    assert!(backend_with(slice.clone(), pod_value()).is_ok());
    let mut pod = pod_value();
    pod["status"]["conditions"] = json!([]);

    assert_unavailable(backend_with(slice, pod), "Ready condition");
}

#[test]
fn numeric_target_mapping_rejects_wildcards_wrong_ports_and_unknown_protocols() {
    for (field, value, reason) in [
        ("port", Value::Null, "wildcard"),
        ("port", json!(0), "1..=65535"),
        ("port", json!(9000), "expected Service targetPort"),
        ("protocol", json!("UDP"), "unknown Service port"),
        ("protocol", json!("SCTP"), "unsupported protocol"),
        ("name", json!("other"), "unknown Service port"),
    ] {
        for ready in [true, false] {
            let mut slice = slice_value();
            slice["ports"][0][field] = value.clone();
            slice["endpoints"][0]["conditions"]["ready"] = json!(ready);

            assert_unsafe(backend_with(slice, pod_value()), reason);
        }
    }

    let mut slice = slice_value();
    let duplicate = slice["ports"][0].clone();
    slice["ports"].as_array_mut().unwrap().push(duplicate);

    assert_unsafe(backend_with(slice, pod_value()), "duplicate port");
}

#[test]
fn unresolved_named_ports_are_unavailable_but_identity_is_still_checked() {
    let mut slice = slice_value();
    slice["ports"] = json!([]);

    assert_unavailable(
        backend_with(slice.clone(), pod_value()),
        "no resolved Service ports",
    );
    slice["endpoints"][0]["targetRef"]["uid"] = json!("wrong");

    assert_unsafe(backend_with(slice, pod_value()), "UID");
}

#[test]
fn named_target_ports_can_resolve_differently_on_different_pods() {
    let mut s = service_value();
    s["spec"]["ports"][0]["targetPort"] = json!("web");
    let s: Service = serde_json::from_value(s).unwrap();
    let request = service_request(&s, &namespace()).unwrap();
    let pod_a: Pod = serde_json::from_value(pod_value()).unwrap();
    let mut pod_b = pod_value();
    pod_b["metadata"]["name"] = json!("web-1");
    pod_b["metadata"]["uid"] = json!("second-pod");
    pod_b["status"]["podIP"] = json!("10.42.0.8");
    pod_b["status"]["podIPs"] = json!([{"ip": "10.42.0.8"}]);
    pod_b["spec"]["containers"][0]["ports"][0]["containerPort"] = json!(9090);
    let pod_b = serde_json::from_value(pod_b).unwrap();
    let slice_a: EndpointSlice = serde_json::from_value(slice_value()).unwrap();
    let mut slice_b = slice_value();
    slice_b["metadata"]["name"] = json!("web-def");
    slice_b["ports"][0]["port"] = json!(9090);
    slice_b["endpoints"][0]["addresses"] = json!(["10.42.0.8"]);
    slice_b["endpoints"][0]["targetRef"]["name"] = json!("web-1");
    slice_b["endpoints"][0]["targetRef"]["uid"] = json!("second-pod");
    let slice_b = serde_json::from_value(slice_b).unwrap();
    let ports = validate_backends(&request, &s, &[slice_a, slice_b], &[pod_a, pod_b]).unwrap();

    assert_eq!(
        ports,
        vec![
            BackendPort {
                protocol: Protocol::Tcp,
                port: 8080
            },
            BackendPort {
                protocol: Protocol::Tcp,
                port: 9090
            },
        ]
    );
}

#[test]
fn named_ports_require_matching_protocol_and_correct_container_port() {
    let mut s = service_value();
    s["spec"]["ports"][0]["targetPort"] = json!("web");

    for (field, value, reason) in [
        ("protocol", json!("UDP"), "no named targetPort"),
        ("containerPort", json!(9090), "resolves to 9090"),
        (
            "containerPort",
            json!(0),
            "containerPort must be in 1..=65535",
        ),
        ("name", json!("other"), "no named targetPort"),
    ] {
        let mut pod = pod_value();
        pod["spec"]["containers"][0]["ports"][0][field] = value;

        assert_unsafe(backend_with_service(s.clone(), slice_value(), pod), reason);
    }

    let mut pod = pod_value();
    let duplicate = pod["spec"]["containers"][0].clone();
    pod["spec"]["containers"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);

    assert_unsafe(
        backend_with_service(s, slice_value(), pod),
        "ambiguous named targetPort",
    );
}

#[test]
fn named_ports_resolve_on_restartable_init_containers_only() {
    let mut s = service_value();
    s["spec"]["ports"][0]["targetPort"] = json!("web");
    let mut pod = pod_value();
    pod["spec"]["containers"][0]["ports"] = json!([]);
    pod["spec"]["initContainers"] = json!([{
        "name": "sidecar", "restartPolicy": "Always",
        "ports": [{"name": "web", "containerPort": 8080}]
    }]);

    assert!(backend_with_service(s.clone(), slice_value(), pod.clone()).is_ok());

    pod["spec"]["initContainers"][0]["restartPolicy"] = Value::Null;

    assert_unsafe(
        backend_with_service(s, slice_value(), pod),
        "no named targetPort",
    );
}

#[test]
fn unnamed_service_port_defaults_target_port_and_protocol() {
    let mut s = service_value();
    s["spec"]["ports"] = json!([{"port": 8080}]);
    let mut slice = slice_value();
    slice["ports"] = json!([{"port": 8080}]);
    let ports = backend_with_service(s, slice, pod_value()).unwrap();

    assert_eq!(
        ports,
        vec![BackendPort {
            protocol: Protocol::Tcp,
            port: 8080
        }]
    );
}

#[test]
fn backend_ports_keep_tcp_and_udp_distinct_at_the_same_number() {
    let mut s = service_value();
    s["spec"]["ports"] = json!([
        {"name": "tcp", "port": 53, "protocol": "TCP", "targetPort": 8080},
        {"name": "udp", "port": 53, "protocol": "UDP", "targetPort": 8080}
    ]);
    let mut slice = slice_value();
    slice["ports"] = json!([
        {"name": "tcp", "port": 8080, "protocol": "TCP"},
        {"name": "udp", "port": 8080, "protocol": "UDP"}
    ]);
    let ports = backend_with_service(s, slice, pod_value()).unwrap();

    assert_eq!(
        ports,
        vec![
            BackendPort {
                protocol: Protocol::Tcp,
                port: 8080
            },
            BackendPort {
                protocol: Protocol::Udp,
                port: 8080
            }
        ]
    );
}

#[test]
fn every_published_service_port_needs_a_ready_backend() {
    let mut s = service_value();
    s["spec"]["ports"].as_array_mut().unwrap().push(json!({
        "name": "dns", "port": 53, "protocol": "UDP", "targetPort": 5353
    }));

    assert_unavailable(
        backend_with_service(s.clone(), slice_value(), pod_value()),
        "dns:53/UDP",
    );

    let service = serde_json::from_value(s).unwrap();
    let request = service_request(&service, &namespace()).unwrap();
    let mut stale = slice_value();
    stale["ports"] = json!([{"name": "dns", "port": 5353, "protocol": "UDP"}]);
    stale["endpoints"][0]["conditions"]["ready"] = json!(false);
    stale["endpoints"][0]["targetRef"]["name"] = json!("gone");

    assert_unavailable(
        validate_backends(
            &request,
            &service,
            &[
                serde_json::from_value(slice_value()).unwrap(),
                serde_json::from_value(stale).unwrap(),
            ],
            &[serde_json::from_value(pod_value()).unwrap()],
        ),
        "dns:53/UDP",
    );
}

#[test]
fn mismatched_request_cannot_reuse_a_previous_selector_or_uid() {
    let s = service();
    let request = service_request(&s, &namespace()).unwrap();
    let mut stale_selector = request.clone();
    stale_selector.selector.insert("app".into(), "other".into());
    let mut stale_uid = request;
    stale_uid.uid = "old-service".into();

    for stale in [stale_selector, stale_uid] {
        assert_unsafe(validate_backends(&stale, &s, &[], &[]), "does not match");
    }
}

#[test]
fn invalid_current_service_keeps_its_service_error_classification() {
    let mut s = service();
    let request = service_request(&s, &namespace()).unwrap();
    s.spec.as_mut().unwrap().external_traffic_policy = Some("Local".into());
    let error = validate_backends(&request, &s, &[], &[]).unwrap_err();

    assert!(matches!(
        error.downcast_ref::<ValidationError>(),
        Some(ValidationError::InvalidService(_))
    ));

    assert!(error.to_string().contains("externalTrafficPolicy"));
}
