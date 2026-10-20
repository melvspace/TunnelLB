use super::*;
use provision::{AllocationOutcome, Operation, ReservationRequest};

fn reservation_request() -> provision::Request {
    let mut request = request();
    request.operation = Operation::Reserve;
    request.generation = Some("a".repeat(64));
    request.reservation = Some(ReservationRequest {
        control_port_range: api::PortRange {
            start: 20000,
            end: 20010,
        },
        excluded_ports: vec![20004],
    });
    request.publication = Some(
        serde_json::from_value(json!({
            "id": "publication-123",
            "serverName": "edge",
            "serverUid": request.server_uid,
            "serverAddress": request.address,
            "controlPort": 0,
            "service": {
                "namespace": "app", "name": "web", "uid": "service-123",
                "clusterIp": "10.96.1.2", "selector": {},
                "ports": [
                    {"name": "https", "port": 443, "protocol": "TCP", "proxyProtocol": "none"},
                    {"name": "dns", "port": 53, "protocol": "UDP", "proxyProtocol": "none"}
                ],
                "servers": ["edge"], "pool": null, "replicas": 1
            }
        }))
        .unwrap(),
    );
    request
}

fn completion(request: &provision::Request, allocation: Value) -> State {
    let mut message: Value = serde_json::from_str(&outcome()).unwrap();
    message["allocation"] = allocation;

    if request.operation == Operation::Enroll && request.expected_known_hosts.is_none() {
        message["architecture"] = json!("");
    }

    result(
        request,
        &terminal(job(), "Complete"),
        &[pod(Some(message.to_string()), 0)],
    )
}

fn assert_invalid(state: State) {
    let State::Failed(error) = state else {
        panic!("expected invalid allocation result");
    };

    assert_eq!(error, "completed SSH Job has an invalid worker result");
}

#[test]
fn reservation_accepts_control_boundaries_and_typed_conflict_results() {
    let request = reservation_request();

    for allocation in [
        AllocationOutcome::Reserved {
            control_port: 20000,
        },
        AllocationOutcome::Reserved {
            control_port: 20005,
        },
        AllocationOutcome::Reserved {
            control_port: 20010,
        },
        AllocationOutcome::PortConflict { port: 443 },
        AllocationOutcome::PortConflict { port: 53 },
        AllocationOutcome::ControlRangeExhausted,
        AllocationOutcome::ReservationChanged,
    ] {
        let State::Complete(outcome) = completion(&request, json!(allocation)) else {
            panic!("valid reservation result rejected");
        };

        assert_eq!(outcome.allocation, Some(allocation));
    }
}

#[test]
fn reservation_rejects_missing_and_malformed_allocation_without_leaking_values() {
    let request = reservation_request();
    assert_invalid(result(
        &request,
        &terminal(job(), "Complete"),
        &[pod(Some(outcome()), 0)],
    ));

    for allocation in [
        Value::Null,
        json!({}),
        json!({"kind": SECRET}),
        json!({"kind": "reserved"}),
        json!({"kind": "reserved", "controlPort": SECRET}),
        json!({"kind": "reserved", "controlPort": -1}),
        json!({"kind": "reserved", "controlPort": 65536}),
        json!({"kind": "reserved", "controlPort": 20000, "error": SECRET}),
        json!({"kind": "portConflict"}),
        json!({"kind": "portConflict", "port": SECRET}),
        json!({"kind": "controlRangeExhausted", "port": 443}),
        json!({"kind": "reservationChanged", "controlPort": 20005}),
        json!([{"kind": "controlRangeExhausted"}]),
    ] {
        assert_invalid(completion(&request, allocation));
    }
}

#[test]
fn reserved_control_obeys_range_exclusions_and_numeric_listener_ownership() {
    let mut request = reservation_request();
    request.ssh_port = 20001;
    let ports = &mut request.publication.as_mut().unwrap().service.ports;
    ports[0].port = 20002;
    ports[1].port = 20003;

    for control_port in [0, 19999, 20011, 20001, 20002, 20003, 20004] {
        assert_invalid(completion(
            &request,
            json!({"kind": "reserved", "controlPort": control_port}),
        ));
    }

    // Zero remains invalid even if it is inside a malformed requested range.
    request
        .reservation
        .as_mut()
        .unwrap()
        .control_port_range
        .start = 0;
    assert_invalid(completion(
        &request,
        json!({"kind": "reserved", "controlPort": 0}),
    ));
    request.reservation = None;
    assert_invalid(completion(
        &request,
        json!({"kind": "reserved", "controlPort": 20005}),
    ));
    request = reservation_request();
    request.publication = None;
    assert_invalid(completion(
        &request,
        json!({"kind": "reserved", "controlPort": 20005}),
    ));
}

#[test]
fn conflicts_must_name_a_requested_public_port() {
    let mut request = reservation_request();

    for port in [0, request.ssh_port, 20000, 20004, 444] {
        assert_invalid(completion(
            &request,
            json!({"kind": "portConflict", "port": port}),
        ));
    }

    request.publication = None;
    assert_invalid(completion(
        &request,
        json!({"kind": "portConflict", "port": 443}),
    ));
}

#[test]
fn other_operations_accept_legacy_results_and_reject_every_allocation_kind() {
    for (operation, pinned) in [
        (Operation::Enroll, true),
        (Operation::Enroll, false),
        (Operation::Apply, true),
        (Operation::Remove, true),
        (Operation::Uninstall, true),
    ] {
        let mut request = reservation_request();
        request.operation = operation;

        if !pinned {
            request.expected_known_hosts = None;
        }

        for allocation in [
            json!({"kind": "reserved", "controlPort": 20005}),
            json!({"kind": "portConflict", "port": 443}),
            json!({"kind": "controlRangeExhausted"}),
            json!({"kind": "reservationChanged"}),
        ] {
            assert_invalid(completion(&request, allocation));
        }

        assert!(matches!(
            completion(&request, Value::Null),
            State::Complete(_)
        ));
        let mut legacy: Value = serde_json::from_str(&outcome()).unwrap();
        legacy.as_object_mut().unwrap().remove("allocation");

        if !pinned {
            legacy["architecture"] = json!("");
        }

        assert!(matches!(
            result(
                &request,
                &terminal(job(), "Complete"),
                &[pod(Some(legacy.to_string()), 0)]
            ),
            State::Complete(_)
        ));
    }
}
