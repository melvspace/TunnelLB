use super::*;

fn pod_spec(job: &mut Job) -> &mut k8s_openapi::api::core::v1::PodSpec {
    job.spec.as_mut().unwrap().template.spec.as_mut().unwrap()
}

fn publication_request(operation: provision::Operation) -> provision::Request {
    let mut request = request();
    request.operation = operation;
    request.publication = Some(
        serde_json::from_value(json!({
            "id": "publication-123",
            "serverName": "edge",
            "serverUid": "server-123",
            "serverAddress": "203.0.113.5",
            "controlPort": 21001,
            "service": {
                "namespace": "app", "name": "web", "uid": "service-123",
                "clusterIp": "10.96.1.2", "selector": {"app": "web"},
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

#[test]
fn only_apply_allows_the_publication_control_port_in_guard_and_policy() {
    use provision::Operation::{Apply, Enroll, Remove, Reserve, Uninstall};

    for operation in [Enroll, Reserve, Apply, Remove, Uninstall] {
        let request = publication_request(operation);
        let artifacts = Artifacts::new(&options(), &server(), &request, "revision").unwrap();
        let pod = artifacts.job.spec.unwrap().template.spec.unwrap();
        let guard = &pod.init_containers.as_ref().unwrap()[0];
        let mut expected_args = vec!["guard", "--allow", "203.0.113.5:22"];
        let mut expected_destinations = json!([
            {"address": "203.0.113.5", "port": 22, "protocol": "TCP"}
        ]);
        let mut expected_egress = json!([{
            "to": [{"ipBlock": {"cidr": "203.0.113.5/32"}}],
            "ports": [{"protocol": "TCP", "port": 22}]
        }]);

        if operation == Apply {
            expected_args.extend(["--control-port", "21001"]);
            expected_destinations.as_array_mut().unwrap().push(json!({
                "address": "203.0.113.5", "port": 21001, "protocol": "TCP"
            }));
            expected_egress.as_array_mut().unwrap().push(json!({
                "to": [{"ipBlock": {"cidr": "203.0.113.5/32"}}],
                "ports": [{"protocol": "TCP", "port": 21001}]
            }));
        }

        let args = guard.args.as_ref().unwrap();
        assert_eq!(*args, expected_args, "{operation:?}");
        let config = crate::connector::GuardConfig::for_ssh(
            args[2].parse().unwrap(),
            args.get(4).map(|port| port.parse().unwrap()),
        );
        config.validate().unwrap();
        assert_eq!(
            json!(config.allowed),
            expected_destinations,
            "{operation:?}"
        );
        let policy = json!(artifacts.policy);
        assert_eq!(
            policy["spec"],
            json!({
                "podSelector": {"matchLabels": {
                    "app.kubernetes.io/managed-by": "tunnellb",
                    "tunnellb.io/ssh-job": artifacts.identity.name
                }},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": expected_egress
            }),
            "{operation:?}"
        );
    }
}

#[test]
fn non_apply_operations_ignore_missing_or_unallocated_control_ports() {
    use provision::Operation::{Enroll, Remove, Reserve, Uninstall};

    for operation in [Enroll, Reserve, Remove, Uninstall] {
        for publication_present in [false, true] {
            let mut request = publication_request(operation);

            if publication_present {
                request.publication.as_mut().unwrap().control_port = 0;
            } else {
                request.publication = None;
            }

            let artifacts = Artifacts::new(&options(), &server(), &request, "revision").unwrap();
            let pod = artifacts.job.spec.unwrap().template.spec.unwrap();
            assert_eq!(
                json!(pod.init_containers.unwrap()[0].args),
                json!(["guard", "--allow", "203.0.113.5:22"]),
                "{operation:?}, publication present: {publication_present}"
            );
            assert_eq!(
                json!(artifacts.policy)["spec"]["egress"],
                json!([{
                    "to": [{"ipBlock": {"cidr": "203.0.113.5/32"}}],
                    "ports": [{"protocol": "TCP", "port": 22}]
                }]),
                "{operation:?}, publication present: {publication_present}"
            );
        }
    }
}

#[test]
fn apply_rejects_missing_zero_or_overlapping_control_port() {
    let mut request = publication_request(provision::Operation::Apply);

    for port in [0, 22, 443, 53] {
        request.publication.as_mut().unwrap().control_port = port;
        assert!(
            Artifacts::new(&options(), &server(), &request, "revision").is_err(),
            "accepted control port {port}"
        );
    }

    request.publication = None;
    assert!(Artifacts::new(&options(), &server(), &request, "revision").is_err());
}

#[test]
fn apply_rejects_publications_and_requests_for_a_different_server() {
    let changes: [fn(&mut provision::Request); 7] = [
        |request| request.publication.as_mut().unwrap().server_uid = "other-uid".into(),
        |request| request.publication.as_mut().unwrap().server_name = "other-name".into(),
        |request| {
            request.publication.as_mut().unwrap().server_address = "203.0.113.6".parse().unwrap();
        },
        |request| request.address = "203.0.113.6".parse().unwrap(),
        |request| request.server_uid = "other-uid".into(),
        |request| request.ssh_port = 2222,
        |request| request.ssh_user = "other-user".into(),
    ];

    for change in changes {
        let mut request = publication_request(provision::Operation::Apply);
        change(&mut request);
        assert!(Artifacts::new(&options(), &server(), &request, "revision").is_err());
    }
}

#[test]
fn content_address_binds_request_and_revision_without_exposing_secrets() {
    let build = |request: &provision::Request, revision| {
        Artifacts::new(&options(), &server(), request, revision).unwrap()
    };

    let original = artifacts();
    let name = &original.identity.name;
    assert_eq!(name, &build(&request(), "revision").identity.name);
    assert_ne!(name, &build(&request(), "other").identity.name);

    let mut changed = request();
    changed.server_private_key = Some("rotated-secret".into());
    assert_ne!(name, &build(&changed, "revision").identity.name);
    assert!(
        !serde_json::to_string(&original.secret.metadata)
            .unwrap()
            .contains(SECRET)
    );
}

#[test]
fn ownership_requires_uid_scope_hash_and_exact_owner() {
    let id = identity();
    let metadata = secret().metadata;
    let owner = job_reference(&job()).unwrap();

    for owners in [None, Some(vec![])] {
        let mut staged = metadata.clone();
        staged.owner_references = owners;
        assert!(id.verify(&staged, None).is_ok());
        assert!(id.verify(&staged, Some(&owner)).is_ok());
    }

    let changes: [fn(&mut Value); 7] = [
        |meta| meta["namespace"] = json!("application"),
        |meta| {
            meta["annotations"]
                .as_object_mut()
                .unwrap()
                .remove(SERVER_UID);
        },
        |meta| meta["annotations"][REQUEST_HASH] = json!("foreign"),
        |meta| meta["ownerReferences"] = json!([server().controller_owner_ref(&()).unwrap()]),
        |meta| meta["annotations"][JOB_UID] = json!("job-123"),
        |meta| meta["labels"][PUBLICATION_LABEL] = json!("foreign"),
        |meta| {
            meta["ownerReferences"] = json!([job_reference(&job()).unwrap()]);
        },
    ];

    for change in changes {
        assert!(id.verify(&mutated(&metadata, change), None).is_err());
    }

    let mut attached = attached(secret()).metadata;
    assert!(id.verify(&attached, Some(&owner)).is_ok());
    assert!(id.verify(&attached, None).is_err());
    let mut recreated = job_reference(&job()).unwrap();
    recreated.uid = "recreated-job".into();
    assert!(id.verify(&attached, Some(&recreated)).is_err());
    attached
        .owner_references
        .as_mut()
        .unwrap()
        .push(owner.clone());
    assert!(id.verify(&attached, Some(&owner)).is_err());
}

#[test]
fn policy_accepts_captured_api_omission_of_empty_ingress() {
    let id = identity();
    let mut wanted = policy();
    wanted.spec =
        resources::ssh_policy(&id.name, "172.28.0.5:22".parse().unwrap(), None, &options()).spec;
    let mut actual = wanted.clone();
    // Shape captured from the isolated e2e API. Only the generated name is
    // replaced with this fixture's name; the server omitted ingress: [].
    actual.spec = Some(
        serde_json::from_value(json!({
            "egress": [{
                "ports": [{"port": 22, "protocol": "TCP"}],
                "to": [{"ipBlock": {"cidr": "172.28.0.5/32"}}]
            }],
            "podSelector": {"matchLabels": {
                "app.kubernetes.io/managed-by": "tunnellb",
                "tunnellb.io/ssh-job": id.name
            }},
            "policyTypes": ["Ingress", "Egress"]
        }))
        .unwrap(),
    );
    assert!(verify_policy(&actual, &wanted, &id, None).is_ok());
    actual.spec.as_mut().unwrap().ingress = Some(vec![Default::default()]);
    assert!(verify_policy(&actual, &wanted, &id, None).is_err());
}

#[test]
fn policy_defaults_do_not_hide_broader_access_or_lost_isolation() {
    let wanted = policy();
    let mut actual = wanted.clone();
    let spec = actual.spec.as_mut().unwrap();
    spec.ingress = None;
    spec.policy_types = None;
    spec.egress.as_mut().unwrap()[0].ports.as_mut().unwrap()[0].protocol = None;
    assert!(verify_policy(&actual, &wanted, &identity(), None).is_ok());
    for change in 0..5 {
        let mut changed = actual.clone();
        let spec = changed.spec.as_mut().unwrap();
        match change {
            0 => spec.egress.as_mut().unwrap().push(Default::default()),
            1 => spec.egress.as_mut().unwrap()[0].to = None,
            2 => spec.pod_selector = None,
            3 => spec.policy_types = Some(vec!["Ingress".into()]),
            _ => spec.egress = Some(vec![Default::default()]),
        }

        assert!(verify_policy(&changed, &wanted, &identity(), None).is_err());
    }

    let mut deny_all = wanted.clone();
    deny_all.spec.as_mut().unwrap().egress = Some(vec![]);
    let mut canonical = deny_all.clone();
    canonical.spec.as_mut().unwrap().egress = None;
    canonical.spec.as_mut().unwrap().ingress = None;
    assert!(verify_policy(&canonical, &deny_all, &identity(), None).is_ok());
    // With no egress rules, omitted policyTypes defaults to Ingress alone.
    canonical.spec.as_mut().unwrap().policy_types = None;
    assert!(verify_policy(&canonical, &deny_all, &identity(), None).is_err());
}

#[test]
fn job_default_normalization_preserves_security_requirements() {
    let wanted = job();
    for change in 0..9 {
        let mut actual = admitted_job(wanted.clone());
        let pod = pod_spec(&mut actual);
        let security = pod.containers[0].security_context.as_mut().unwrap();
        match change {
            0 => pod.host_network = Some(true),
            1 => pod.host_pid = Some(true),
            2 => pod.host_ipc = Some(true),
            3 => pod.containers[0].volume_mounts.as_mut().unwrap()[0].read_only = None,
            4 => security.run_as_non_root = None,
            5 => security.allow_privilege_escalation = None,
            6 => pod.automount_service_account_token = None,
            7 => pod.enable_service_links = None,
            _ => pod.containers[0].image = Some("foreign-worker".into()),
        }

        assert!(
            verify_job(&actual, &wanted, &identity()).is_err(),
            "accepted unsafe change {change}"
        );
    }
}
