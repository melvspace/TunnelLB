use super::*;

fn pod_spec(job: &mut Job) -> &mut k8s_openapi::api::core::v1::PodSpec {
    job.spec.as_mut().unwrap().template.spec.as_mut().unwrap()
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
        resources::ssh_policy(&id.name, "172.28.0.5".parse().unwrap(), 22, &options()).spec;
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
