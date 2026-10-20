use anyhow::Result;
use http::{Request as HttpRequest, Response};
use kube::{Api, Client, client::Body};
use serde::Serialize;
use std::{
    collections::VecDeque,
    convert::Infallible,
    sync::{Arc, Mutex},
};
use tower::service_fn;

use super::super::{cleanup, run, runtime::attach_to_job};
use super::*;

struct Exchange {
    method: &'static str,
    path: String,
    status: u16,
    response: Box<dyn FnOnce(Value) -> Value + Send>,
}

impl Exchange {
    fn reply(method: &'static str, resource: &str, status: u16, response: impl Serialize) -> Self {
        let response = json!(response);
        Self::inspect(method, resource, status, move |_| response)
    }

    fn inspect(
        method: &'static str,
        resource: &str,
        status: u16,
        response: impl FnOnce(Value) -> Value + Send + 'static,
    ) -> Self {
        Self {
            method,
            path: path(resource, method == "POST"),
            status,
            response: Box::new(response),
        }
    }

    fn get(resource: &str, response: impl Serialize) -> Self {
        Self::reply("GET", resource, 200, response)
    }

    fn create_unowned(resource: &str, response: impl Serialize) -> Self {
        let response = json!(response);
        Self::inspect("POST", resource, 201, move |body| {
            let owners = body["metadata"]["ownerReferences"].as_array();
            assert!(
                owners.is_none_or(Vec::is_empty),
                "artifact must survive Machine deletion"
            );
            response
        })
    }

    fn list(resource: &str, items: Value) -> Self {
        let kind = match resource {
            "jobs" => "JobList",
            "secrets" => "SecretList",
            "networkpolicies" => "NetworkPolicyList",
            "pods" => "PodList",
            _ => panic!("unexpected resource"),
        };

        let mut exchange = Self::get(
            resource,
            json!({"apiVersion": "v1", "kind": kind, "metadata": {}, "items": items}),
        );
        exchange.path = path(resource, true);
        exchange
    }
}

fn mock(exchanges: Vec<Exchange>) -> (Client, Arc<Mutex<VecDeque<Exchange>>>) {
    let queue = Arc::new(Mutex::new(VecDeque::from(exchanges)));
    let calls = queue.clone();
    let service = service_fn(move |request: HttpRequest<Body>| {
        let exchange = calls
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected API request");
        async move {
            assert_eq!(request.method().as_str(), exchange.method);
            assert_eq!(request.uri().path(), exchange.path);
            let body = request.into_body().collect_bytes().await.unwrap();
            let body = if body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&body).unwrap()
            };

            let value = (exchange.response)(body);
            Ok::<_, Infallible>(
                Response::builder()
                    .status(exchange.status)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&value).unwrap()))
                    .unwrap(),
            )
        }
    });
    (Client::new(service, "wrong-default-namespace"), queue)
}

fn path(resource: &str, collection: bool) -> String {
    let prefix = match resource {
        "jobs" => "/apis/batch/v1",
        "networkpolicies" => "/apis/networking.k8s.io/v1",
        _ => "/api/v1",
    };

    let base = format!("{prefix}/namespaces/{NAMESPACE}/{resource}");

    if collection {
        base
    } else {
        format!("{base}/{}", identity().name)
    }
}

fn status(code: u16) -> Value {
    json!({"apiVersion": "v1", "kind": "Status", "status": "Failure",
        "code": code, "reason": if code == 404 { "NotFound" } else { "Conflict" }, "message": SECRET})
}

fn missing() -> Vec<Exchange> {
    ["jobs", "secrets", "networkpolicies"]
        .iter()
        .map(|resource| Exchange::reply("GET", resource, 404, status(404)))
        .collect()
}

fn before_create(older_jobs: Value) -> Vec<Exchange> {
    let mut exchanges = missing();
    exchanges.push(Exchange::list("jobs", older_jobs));
    exchanges
}

fn created_artifacts() -> Vec<Exchange> {
    let mut canonical_policy = policy();
    canonical_policy.spec.as_mut().unwrap().ingress = None;
    vec![
        Exchange::create_unowned("secrets", secret()),
        Exchange::create_unowned("networkpolicies", canonical_policy),
        Exchange::create_unowned("jobs", admitted_job(job())),
        Exchange::reply("PATCH", "secrets", 200, attached(secret())),
        Exchange::reply("PATCH", "networkpolicies", 200, attached(policy())),
    ]
}

fn earlier_job() -> Job {
    Artifacts::new(&options(), &machine(), &request(), "earlier-revision")
        .unwrap()
        .job
}

async fn reconcile(exchanges: Vec<Exchange>) -> Result<State> {
    let (client, queue) = mock(exchanges);
    let result = run(&client, &options(), &machine(), &request(), "revision").await;
    assert!(queue.lock().unwrap().is_empty());
    result
}

async fn bind_secret(exchanges: Vec<Exchange>) -> Result<()> {
    let (client, queue) = mock(exchanges);
    let id = identity();
    let wanted = secret();
    let owner = job_reference(&job()).unwrap();
    let result = attach_to_job(
        &Api::<Secret>::namespaced(client, NAMESPACE),
        wanted.clone(),
        &id,
        &owner,
        |actual| verify_secret(actual, &wanted, &id, Some(&owner)),
    )
    .await;
    assert!(queue.lock().unwrap().is_empty());
    result
}

async fn clean(exchanges: Vec<Exchange>, selector: &str) -> Result<()> {
    let (client, queue) = mock(exchanges);
    let result = cleanup(&client, NAMESPACE, selector).await;
    assert!(queue.lock().unwrap().is_empty());
    result
}

#[tokio::test]
async fn foreign_create_conflict_is_not_adopted_or_followed_by_a_job() {
    let foreign = machine_owned(secret());
    let mut exchanges = before_create(json!([]));
    exchanges.extend([
        Exchange::reply("POST", "secrets", 409, status(409)),
        Exchange::get("secrets", foreign),
    ]);
    let error = reconcile(exchanges).await.unwrap_err();
    assert!(error.to_string().contains("foreign owner"));
    assert!(!format!("{error:?}").contains(SECRET));
}

#[tokio::test]
async fn foreign_existing_policy_prevents_all_mutations() {
    let foreign = machine_owned(policy());
    let mut exchanges = missing();
    exchanges[2] = Exchange::get("networkpolicies", foreign);
    assert!(reconcile(exchanges).await.is_err());
}

#[tokio::test]
async fn owner_patch_conflict_rejects_replaced_or_modified_artifact() {
    for replaced in [true, false] {
        let mut changed = secret();

        if replaced {
            changed.metadata.uid = Some("replacement".into());
        } else {
            changed.data.as_mut().unwrap().clear();
        }

        let result = bind_secret(vec![
            Exchange::inspect("PATCH", "secrets", 409, |patch| {
                assert_eq!(patch["metadata"]["uid"], "secret-123");
                assert_eq!(patch["metadata"]["resourceVersion"], "8");
                assert_eq!(
                    patch["metadata"]["ownerReferences"],
                    json!([job_reference(&job()).unwrap()])
                );
                assert_eq!(patch["metadata"]["annotations"][JOB_UID], "job-123");
                assert!(patch.get("data").is_none());
                status(409)
            }),
            Exchange::get("secrets", changed),
        ])
        .await;
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn create_order_owner_binding_and_repeated_reconciliation_are_idempotent() {
    let mut exchanges = before_create(json!([]));
    exchanges.extend(created_artifacts());
    exchanges.extend([
        Exchange::get("jobs", job()),
        Exchange::get("secrets", attached(secret())),
        Exchange::get("networkpolicies", attached(policy())),
    ]);
    let (client, queue) = mock(exchanges);

    for _ in 0..2 {
        assert!(matches!(
            run(&client, &options(), &machine(), &request(), "revision")
                .await
                .unwrap(),
            State::Pending
        ));
    }

    assert!(queue.lock().unwrap().is_empty());
}

#[tokio::test]
async fn new_revision_waits_for_same_machine_across_publications() {
    let mut older = earlier_job();
    older
        .metadata
        .labels
        .as_mut()
        .unwrap()
        .insert(PUBLICATION_LABEL.into(), "other-publication".into());
    assert!(matches!(
        reconcile(before_create(json!([older]))).await.unwrap(),
        State::Pending
    ));
}

#[tokio::test]
async fn new_revision_ignores_finished_or_foreign_jobs() {
    let mut other_uid = earlier_job();
    other_uid
        .metadata
        .annotations
        .as_mut()
        .unwrap()
        .insert(MACHINE_UID.into(), "other-machine-uid".into());
    let mut other_machine = earlier_job();
    other_machine
        .metadata
        .labels
        .as_mut()
        .unwrap()
        .insert(api::MACHINE_LABEL.into(), "other-machine".into());

    for older in [
        terminal(earlier_job(), "Complete"),
        terminal(earlier_job(), "Failed"),
        other_uid,
        other_machine,
        machine_owned(earlier_job()),
    ] {
        let mut exchanges = before_create(json!([older]));
        exchanges.extend(created_artifacts());
        assert!(matches!(
            reconcile(exchanges).await.unwrap(),
            State::Pending
        ));
    }
}

#[tokio::test]
async fn machine_job_list_errors_do_not_leak_credentials() {
    let mut exchanges = before_create(json!([]));
    let list = exchanges.last_mut().unwrap();
    list.status = 503;
    list.response = Box::new(|_| status(503));
    let error = reconcile(exchanges).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("list SSH Jobs failed (Kubernetes HTTP 503)")
    );
    assert!(!format!("{error:?}").contains(SECRET));
}

#[tokio::test]
async fn completed_run_reads_both_pod_labels_and_deduplicates_result() {
    let workers = json!([pod(Some(outcome()), 0)]);
    let result = reconcile(vec![
        Exchange::get("jobs", terminal(job(), "Complete")),
        Exchange::get("secrets", attached(secret())),
        Exchange::get("networkpolicies", attached(policy())),
        Exchange::list("pods", workers.clone()),
        Exchange::list("pods", workers),
    ])
    .await
    .unwrap();
    let State::Complete(outcome) = result else {
        panic!("valid worker result was lost");
    };

    assert_eq!(outcome.architecture, "amd64");
}

#[tokio::test]
async fn owner_patch_retries_only_the_same_verified_object() {
    let mut concurrent = secret();
    concurrent.metadata.resource_version = Some("11".into());
    let saved = attached(concurrent.clone());
    bind_secret(vec![
        Exchange::reply("PATCH", "secrets", 409, status(409)),
        Exchange::get("secrets", concurrent),
        Exchange::inspect("PATCH", "secrets", 200, move |patch| {
            assert_eq!(patch["metadata"]["uid"], "secret-123");
            assert_eq!(patch["metadata"]["resourceVersion"], "11");
            json!(saved)
        }),
    ])
    .await
    .unwrap();
}

#[tokio::test]
async fn cleanup_preserves_foreign_credentials_connectors_and_pin_secrets() {
    let foreign = machine_owned(job());
    let mut connector = secret();
    connector
        .metadata
        .labels
        .as_mut()
        .unwrap()
        .insert(KIND_LABEL.into(), "connector".into());
    let secrets = ["ssh-privatekey", "known_hosts"].map(|key| {
        let mut credentials = secret();
        credentials.data = Some(BTreeMap::from([(key.into(), ByteString(vec![1]))]));
        credentials
    });
    let foreign_policy = machine_owned(policy());
    let mut exchanges = vec![
        Exchange::list("jobs", json!([job(), foreign])),
        Exchange::list(
            "secrets",
            json!([secret(), connector, secrets[0], secrets[1]]),
        ),
        Exchange::list("networkpolicies", json!([policy(), foreign_policy])),
    ];

    for (resource, uid, version) in [
        ("jobs", "job-123", "10"),
        ("secrets", "secret-123", "8"),
        ("networkpolicies", "policy-123", "9"),
    ] {
        exchanges.push(Exchange::inspect("DELETE", resource, 200, move |body| {
            assert_eq!(body["preconditions"]["uid"], uid);
            assert_eq!(body["preconditions"]["resourceVersion"], version);
            json!({"apiVersion":"v1", "kind":"Status", "status":"Success"})
        }));
    }

    clean(exchanges, &format!("{}=edge", api::MACHINE_LABEL))
        .await
        .unwrap();
}

#[tokio::test]
async fn cleanup_removes_verified_leftovers_after_the_job_is_gone() {
    let leftover = attached(secret());
    let mut foreign = leftover.clone();
    foreign.metadata.owner_references.as_mut().unwrap()[0].uid = "foreign-job".into();
    clean(
        vec![
            Exchange::list("jobs", json!([])),
            Exchange::list("secrets", json!([leftover, foreign])),
            Exchange::list("networkpolicies", json!([])),
            Exchange::reply("GET", "jobs", 404, status(404)),
            Exchange::reply(
                "DELETE",
                "secrets",
                200,
                json!({"apiVersion":"v1", "kind":"Status", "status":"Success"}),
            ),
        ],
        "",
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn cleanup_does_not_retry_after_concurrent_owner_change() {
    let error = clean(
        vec![
            Exchange::list("jobs", json!([])),
            Exchange::list("secrets", json!([secret()])),
            Exchange::list("networkpolicies", json!([])),
            Exchange::reply("DELETE", "secrets", 409, status(409)),
        ],
        "",
    )
    .await
    .unwrap_err();
    assert!(!format!("{error:?}").contains(SECRET));
}
