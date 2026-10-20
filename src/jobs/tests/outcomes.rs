use super::super::runtime::api_error;
use super::*;

fn completion(pods: &[Pod]) -> State {
    result(&request(), &terminal(job(), "Complete"), pods)
}

#[test]
fn failed_pod_count_is_pending_until_job_finishes_retrying() {
    let mut retrying = job();
    retrying.status = Some(JobStatus {
        failed: Some(1),
        active: Some(1),
        ..Default::default()
    });
    assert!(matches!(
        result(&request(), &retrying, &[pod(Some(outcome()), 0)]),
        State::Pending
    ));
    assert!(matches!(
        result(
            &request(),
            &terminal(job(), "Failed"),
            &[pod(Some(outcome()), 0)]
        ),
        State::Failed(_)
    ));
}

#[test]
fn completed_job_requires_owned_current_worker_success() {
    assert!(matches!(
        completion(&[pod(Some(outcome()), 0)]),
        State::Complete(_)
    ));
    let changes: [fn(&mut Value); 7] = [
        |pod| pod["metadata"]["ownerReferences"][0]["uid"] = json!("other-job"),
        |pod| pod["metadata"]["labels"] = Value::Null,
        |pod| pod["status"]["containerStatuses"][0]["name"] = json!("sidecar"),
        |pod| {
            let worker = &mut pod["status"]["containerStatuses"][0];
            worker["lastState"] = worker["state"].take();
        },
        |pod| pod["status"]["containerStatuses"][0]["state"]["terminated"]["exitCode"] = json!(1),
        |pod| pod["metadata"]["namespace"] = json!("other"),
        |pod| pod["metadata"]["ownerReferences"][0]["controller"] = json!(false),
    ];

    for change in changes {
        let wrong = mutated(&pod(Some(outcome()), 0), change);
        assert!(matches!(completion(&[wrong]), State::Failed(_)));
    }

    let mut legacy = pod(Some(outcome()), 0);
    legacy.metadata.labels = Some(BTreeMap::from([("job-name".into(), job().name_any())]));
    assert!(matches!(completion(&[legacy]), State::Complete(_)));
    assert!(matches!(completion(&[]), State::Failed(_)));
}

#[test]
fn only_unpinned_enrollment_accepts_discovery_without_architecture() {
    use provision::Operation::{Apply, Enroll, Remove, Uninstall};

    for (operation, pinned, architecture, accepted) in [
        (Enroll, false, "", true),
        (Enroll, true, "", false),
        (Apply, false, "", false),
        (Remove, false, "", false),
        (Uninstall, false, "", false),
        (Enroll, false, "amd64", false),
    ] {
        let mut request = request();
        request.operation = operation;

        if !pinned {
            request.expected_known_hosts = None;
        }

        let mut discovered: Value = serde_json::from_str(&outcome()).unwrap();
        discovered["architecture"] = architecture.into();
        let pods = [pod(Some(discovered.to_string()), 0)];
        let state = result(&request, &terminal(job(), "Complete"), &pods);
        assert_eq!(
            matches!(state, State::Complete(_)),
            accepted,
            "{operation:?}, pinned={pinned}"
        );
    }
}

#[test]
fn completed_job_rejects_ambiguous_malformed_missing_and_oversized_results() {
    assert!(matches!(
        completion(&[pod(Some(outcome()), 0), pod(Some(outcome()), 0)]),
        State::Failed(_)
    ));
    for message in [
        None,
        Some(String::new()),
        Some("{}".into()),
        Some("{".into()),
        Some(format!("{} trailing {SECRET}", outcome())),
        Some(json!({"error": SECRET}).to_string()),
        Some(json!({"knownHosts": "", "fingerprint": "SHA256:", "architecture": "amd64"}).to_string()),
        Some(json!({"knownHosts": "host key", "fingerprint": "SHA256:test", "architecture": "unknown"}).to_string()),
        Some("🦀".repeat(2048)),
    ] {
        let State::Failed(error) = completion(&[pod(message, 0)]) else {
            panic!("false success");
        };

        assert!(!error.contains(SECRET));
    }

    let exact = format!(
        "{}{}",
        outcome(),
        " ".repeat(RESULT_LIMIT - outcome().len())
    );
    assert!(matches!(
        completion(&[pod(Some(exact.clone()), 0)]),
        State::Complete(_)
    ));
    assert!(matches!(
        completion(&[pod(Some(exact + " "), 0)]),
        State::Failed(_)
    ));
}

#[test]
fn worker_and_kubernetes_errors_never_retain_credential_strings() {
    let mut failed = terminal(job(), "Failed");
    failed.status.as_mut().unwrap().conditions.as_mut().unwrap()[0].reason = Some(SECRET.into());
    let State::Failed(error) = result(
        &request(),
        &failed,
        &[pod(Some(json!({"error": SECRET}).to_string()), 1)],
    ) else {
        panic!("expected failure");
    };

    assert!(error.contains("worker reported a provisioning error"));
    assert!(!error.contains(SECRET));
    let error = api_error(
        "create SSH artifact",
        kube::Error::Api(
            kube::core::Status::failure(SECRET, SECRET)
                .with_code(422)
                .boxed(),
        ),
    );
    for formatted in [
        format!("{error}"),
        format!("{error:?}"),
        format!("{error:#}"),
    ] {
        assert!(!formatted.contains(SECRET));
        assert!(formatted.contains("422"));
    }
}
