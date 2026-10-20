use super::{
    Config, Context,
    publication::{ensure_publication, publication_hash, publication_id},
    service::{reconcile_service, service_inner},
};
use std::{
    collections::{BTreeMap, VecDeque},
    convert::Infallible,
    sync::{Arc, Mutex as StdMutex},
};

use http::{Request as HttpRequest, Response};
use k8s_openapi::{
    ByteString,
    api::core::v1::{Secret, Service},
};
use kube::{Client, client::Body};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tower::service_fn;

use crate::{
    api::*,
    provision::{Operation, Request},
    resources::ResourceOptions,
    store::{PublicationRecord, Store},
};

const OPERATOR: &str = "operator";
const TENANT: &str = "application";

mod reservations;

struct Exchange {
    method: &'static str,
    path: String,
    status: u16,
    respond: Box<dyn FnOnce(Value) -> Value + Send>,
}

impl Exchange {
    fn get(path: String, response: Value) -> Self {
        Self::reply("GET", path, 200, response)
    }

    fn reply(method: &'static str, path: String, status: u16, response: Value) -> Self {
        Self::inspect(method, path, status, move |_| response)
    }

    fn inspect(
        method: &'static str,
        path: String,
        status: u16,
        respond: impl FnOnce(Value) -> Value + Send + 'static,
    ) -> Self {
        Self {
            method,
            path,
            status,
            respond: Box::new(respond),
        }
    }
}

fn mock(exchanges: Vec<Exchange>) -> (Arc<Context>, Arc<StdMutex<VecDeque<Exchange>>>) {
    let queue = Arc::new(StdMutex::new(VecDeque::from(exchanges)));
    let calls = queue.clone();
    let service = service_fn(move |request: HttpRequest<Body>| {
        let exchange = calls.lock().unwrap().pop_front().unwrap_or_else(|| {
            panic!(
                "unexpected API request: {} {}",
                request.method(),
                request.uri()
            )
        });
        async move {
            assert_eq!(request.method().as_str(), exchange.method);
            let path = request.uri().path();

            // Only content-addressed Job names vary with the clock.
            if let Some(prefix) = exchange.path.strip_suffix('*') {
                let suffix = path.strip_prefix(prefix).expect("unexpected Job API path");
                assert_eq!(suffix.len(), 32);
                assert!(suffix.bytes().all(|b| b.is_ascii_hexdigit()));
            } else {
                assert_eq!(path, exchange.path);
            }

            let bytes = request.into_body().collect_bytes().await.unwrap();
            let body = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            let response = (exchange.respond)(body);
            Ok::<_, Infallible>(
                Response::builder()
                    .status(exchange.status)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&response).unwrap()))
                    .unwrap(),
            )
        }
    });
    let client = Client::new(service, "wrong-default-namespace");
    let config = Config {
        namespace: OPERATOR.into(),
        image: "tunnellb:test".into(),
        image_pull_policy: "IfNotPresent".into(),
        worker_service_account: "tunnellb-worker".into(),
        allow_private_machines: false,
        requeue_seconds: 10,
        health_address: "127.0.0.1:0".parse().unwrap(),
    };

    (
        Arc::new(Context {
            store: Store::new(client.clone(), config.namespace.clone()),
            resources: ResourceOptions {
                namespace: config.namespace.clone(),
                image: config.image.clone(),
                pull_policy: config.image_pull_policy.clone(),
                service_account: config.worker_service_account.clone(),
            },
            client,
            config,
            serial: Mutex::new(()),
        }),
        queue,
    )
}

fn path(resource: &str, name: &str) -> String {
    let prefix = match resource {
        "deployments" | "replicasets" => "/apis/apps/v1",
        "jobs" => "/apis/batch/v1",
        "networkpolicies" => "/apis/networking.k8s.io/v1",
        _ => "/api/v1",
    };
    let collection = format!("{prefix}/namespaces/{OPERATOR}/{resource}");

    if name.is_empty() {
        collection
    } else {
        format!("{collection}/{name}")
    }
}

fn status(code: u16) -> Value {
    json!({
        "apiVersion": "v1", "kind": "Status", "code": code,
        "status": if code < 400 { "Success" } else { "Failure" },
        "reason": match code {
            403 => "Forbidden",
            404 => "NotFound",
            503 => "ServiceUnavailable",
            _ => "Success",
        },
    })
}

fn list(kind: &str, items: Vec<Value>) -> Value {
    json!({"apiVersion": "v1", "kind": format!("{kind}List"), "metadata": {}, "items": items})
}

fn record() -> PublicationRecord {
    serde_json::from_value(json!({
        "publication": {
            "id": publication_id("service-uid", "machine-uid"),
            "machineName": "edge", "machineUid": "machine-uid",
            "machineAddress": "8.8.8.8", "controlPort": 20000,
            "service": {
                "namespace": TENANT, "name": "web", "uid": "service-uid",
                "clusterIp": "10.96.1.10", "selector": {"app": "web"},
                "ports": [{"name": "https", "port": 443, "protocol": "TCP", "proxyProtocol": "none"}],
                "machines": [], "pool": null, "replicas": 1,
            },
        },
        "machine_spec": {
            "address": "8.8.8.8",
            "ssh": {"user": "root", "port": 22, "privateKeySecretRef": {"name": "administrator-key"}},
        },
        "backend_ports": [{"protocol": "TCP", "port": 8443}],
        "config_hash": "desired-hash", "applied_hash": "desired-hash",
        "published": true, "removing": false, "reserved": true,
        "credential_generation": "a".repeat(64),
    }))
    .unwrap()
}

fn service() -> Service {
    serde_json::from_value(json!({
        "metadata": {
            "name": "web", "namespace": TENANT, "uid": "service-uid",
            "resourceVersion": "11", "generation": 2, "finalizers": [FINALIZER],
        },
        "spec": {
            "type": "LoadBalancer", "loadBalancerClass": CLASS,
            "allocateLoadBalancerNodePorts": false, "clusterIP": "10.96.1.10",
            "selector": {"app": "web"},
            "ports": [{"name": "https", "port": 443, "targetPort": 8443, "protocol": "TCP"}],
        },
        "status": {"loadBalancer": {"ingress": [{"ip": "8.8.8.8", "ipMode": "Proxy"}]}},
    }))
    .unwrap()
}

fn record_object(record: &PublicationRecord) -> Value {
    let p = &record.publication;
    json!({
        "metadata": {
            "name": p.id, "namespace": OPERATOR, "uid": "record-uid", "resourceVersion": "7",
            "labels": {
                MANAGED_LABEL: "tunnellb", PUBLICATION_LABEL: p.id,
                MACHINE_LABEL: p.machine_name, SERVICE_UID_LABEL: p.service.uid,
                "tunnellb.io/kind": "publication", "tunnellb.io/machine-uid": p.machine_uid,
            },
        },
        "data": {"record.json": serde_json::to_string(record).unwrap()},
    })
}

fn records(record: &PublicationRecord) -> Exchange {
    Exchange::get(
        path("configmaps", ""),
        list("ConfigMap", vec![record_object(record)]),
    )
}

fn mark_removing(record: &PublicationRecord, code: u16) -> Vec<Exchange> {
    let mut expected = record.clone();
    expected.removing = true;
    save_record(record, &expected, code)
}

fn save_record(
    record: &PublicationRecord,
    expected: &PublicationRecord,
    code: u16,
) -> Vec<Exchange> {
    let expected = expected.clone();
    vec![
        Exchange::get(
            path("configmaps", &record.publication.id),
            record_object(record),
        ),
        Exchange::inspect(
            "PUT",
            path("configmaps", &record.publication.id),
            code,
            move |mut body| {
                let actual: Value =
                    serde_json::from_str(body["data"]["record.json"].as_str().unwrap()).unwrap();
                assert_eq!(actual, json!(expected));
                assert_eq!(body["metadata"]["resourceVersion"], "7");
                assert_eq!(body["metadata"]["uid"], "record-uid");
                body["metadata"]["resourceVersion"] = "8".into();

                if code == 200 { body } else { status(code) }
            },
        ),
    ]
}

fn connector_termination(record: &PublicationRecord, present: bool, delete: bool) -> Vec<Exchange> {
    let id = &record.publication.id;
    let mut deployment = json!({
        "metadata": {
            "name": id, "namespace": OPERATOR, "uid": "connector-uid", "resourceVersion": "9",
            "labels": {MANAGED_LABEL: "tunnellb", PUBLICATION_LABEL: id},
        },
    });

    if !delete {
        deployment["metadata"]["deletionTimestamp"] = "2026-01-01T00:00:00Z".into();
    }

    let mut exchanges = vec![Exchange::reply(
        "GET",
        path("deployments", id),
        if present { 200 } else { 404 },
        if present {
            deployment.clone()
        } else {
            status(404)
        },
    )];

    if present && delete {
        exchanges.push(Exchange::inspect(
            "DELETE",
            path("deployments", id),
            200,
            |body| {
                assert_eq!(body["preconditions"]["uid"], "connector-uid");
                assert_eq!(body["propagationPolicy"], "Foreground");
                status(200)
            },
        ));
    }

    deployment["metadata"]["deletionTimestamp"] = "2026-01-01T00:00:00Z".into();
    exchanges.extend([
        Exchange::get(path("pods", ""), list("Pod", vec![])),
        Exchange::reply(
            "GET",
            path("deployments", id),
            if present { 200 } else { 404 },
            if present { deployment } else { status(404) },
        ),
        Exchange::get(path("replicasets", ""), list("ReplicaSet", vec![])),
    ]);
    exchanges
}

fn assigned_machine(record: &PublicationRecord) -> Machine {
    let mut machine = Machine::new("edge", record.machine_spec.clone());
    machine.metadata.uid = Some(record.publication.machine_uid.clone());
    machine.status = Some(MachineStatus {
        phase: "Ready".into(),
        ..Default::default()
    });
    machine
}

fn unavailable_backend(record: &PublicationRecord, machines: &[Machine]) -> Vec<Exchange> {
    vec![
        records(record),
        Exchange::get(
            format!("/api/v1/namespaces/{TENANT}"),
            json!({"metadata": {"name": TENANT, "labels": {ENABLED_LABEL: "true"}}}),
        ),
        Exchange::get(
            format!("/apis/discovery.k8s.io/v1/namespaces/{TENANT}/endpointslices"),
            list("EndpointSlice", vec![]),
        ),
        Exchange::get(
            format!("/api/v1/namespaces/{TENANT}/pods"),
            list("Pod", vec![]),
        ),
        Exchange::get(
            "/apis/tunnellb.io/v1alpha1/machines".into(),
            list("Machine", machines.iter().map(|m| json!(m)).collect()),
        ),
        Exchange::get("/api/v1/nodes".into(), list("Node", vec![])),
    ]
}

fn ready_backend(
    record: &PublicationRecord,
    service: &Service,
    machines: &[Machine],
) -> Vec<Exchange> {
    let mut exchanges = unavailable_backend(record, machines);
    let port = &service.spec.as_ref().unwrap().ports.as_ref().unwrap()[0];
    exchanges[2] = Exchange::get(
        format!("/apis/discovery.k8s.io/v1/namespaces/{TENANT}/endpointslices"),
        list(
            "EndpointSlice",
            vec![json!({
                "metadata": {
                    "name": "web-abc", "namespace": TENANT,
                    "labels": {
                        "kubernetes.io/service-name": "web",
                        "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io",
                    },
                    "ownerReferences": [{
                        "apiVersion": "v1", "kind": "Service", "name": "web",
                        "uid": "service-uid", "controller": true,
                    }],
                },
                "addressType": "IPv4",
                "ports": [{"name": port.name, "port": 8443, "protocol": "TCP"}],
                "endpoints": [{
                    "addresses": ["10.244.1.2"], "conditions": {"ready": true},
                    "targetRef": {"kind": "Pod", "name": "web-pod", "namespace": TENANT, "uid": "pod-uid"},
                }],
            })],
        ),
    );
    exchanges[3] = Exchange::get(
        format!("/api/v1/namespaces/{TENANT}/pods"),
        list(
            "Pod",
            vec![json!({
                "metadata": {"name": "web-pod", "namespace": TENANT, "uid": "pod-uid", "labels": {"app": "web"}},
                "spec": {"containers": [{"name": "web", "image": "example:test"}]},
                "status": {"phase": "Running", "podIP": "10.244.1.2", "conditions": [{"type": "Ready", "status": "True"}]},
            })],
        ),
    );
    exchanges
}

fn condition(service: &Service, reason: &'static str, retains_ips: bool) -> Exchange {
    let response = json!(service);
    Exchange::inspect(
        "PATCH",
        format!("/api/v1/namespaces/{TENANT}/services/web/status"),
        200,
        move |body| {
            assert_eq!(body["status"]["conditions"][0]["reason"], reason);

            if retains_ips {
                assert_eq!(
                    body["status"]["loadBalancer"],
                    response["status"]["loadBalancer"]
                );
            }

            response
        },
    )
}

#[tokio::test]
async fn unavailable_backends_keep_an_unchanged_connector_and_publication() {
    let record = record();
    let service = service();
    let mut exchanges = unavailable_backend(&record, &[assigned_machine(&record)]);
    exchanges.push(Exchange::get(
        path("deployments", &record.publication.id),
        json!({
            "spec": {
                "selector": {},
                "template": {"metadata": {"annotations": {"tunnellb.io/config-hash": record.config_hash}}},
            },
        }),
    ));
    exchanges.push(condition(&service, "BackendUnavailable", true));
    let (context, queue) = mock(exchanges);
    service_inner(&service, &context).await.unwrap();
    // No Deployment, lease, credential, or publication-record mutation.
    assert!(queue.lock().unwrap().is_empty());
}

#[tokio::test]
async fn backend_unavailability_does_not_hide_destination_or_authorization_changes() {
    for change in [
        "ip",
        "selector",
        "port",
        "machine-authorization",
        "selection",
    ] {
        let record = record();
        let mut service = service();
        let mut machine = assigned_machine(&record);

        match change {
            "ip" => service.spec.as_mut().unwrap().cluster_ip = Some("10.96.1.11".into()),
            "selector" => {
                service.spec.as_mut().unwrap().selector =
                    Some(BTreeMap::from([("app".into(), "other".into())]));
            }
            "port" => service.spec.as_mut().unwrap().ports.as_mut().unwrap()[0].port = 444,
            "machine-authorization" => machine.spec.allowed_namespaces = vec!["other".into()],
            "selection" => {
                service.metadata.annotations = Some(BTreeMap::from([(
                    "tunnellb.io/machines".into(),
                    "other".into(),
                )]));
            }
            _ => unreachable!(),
        }

        let mut exchanges = unavailable_backend(&record, &[machine]);
        exchanges.extend(mark_removing(&record, 200));
        exchanges.extend(connector_termination(&record, true, true));
        exchanges.push(condition(&service, "Reconfiguring", false));
        let (context, queue) = mock(exchanges);
        service_inner(&service, &context).await.unwrap();
        assert!(queue.lock().unwrap().is_empty(), "{change}");
    }
}

#[tokio::test]
async fn duplicate_address_suspends_connector_without_removing_its_assignment() {
    let record = record();
    let service = service();
    let machine = assigned_machine(&record);
    let mut duplicate = machine.clone();
    duplicate.metadata.name = Some("duplicate".into());
    duplicate.metadata.uid = Some("duplicate-uid".into());
    let mut exchanges = unavailable_backend(&record, &[machine, duplicate]);
    exchanges.extend(connector_termination(&record, true, true));
    exchanges.push(condition(&service, "AddressConflict", true));
    let (context, queue) = mock(exchanges);
    service_inner(&service, &context).await.unwrap();
    // No removing marker, ledger mutation, credential deletion, or reallocation.
    assert!(queue.lock().unwrap().is_empty());
}

#[tokio::test]
async fn namespace_revocation_and_unverifiable_routed_endpoints_stop_connectors() {
    for namespace_revoked in [false, true] {
        let record = record();
        let service = service();
        let mut exchanges = ready_backend(&record, &service, &[assigned_machine(&record)]);

        if namespace_revoked {
            exchanges.truncate(2);
            exchanges[1] = Exchange::get(
                format!("/api/v1/namespaces/{TENANT}"),
                json!({"metadata": {"name": TENANT}}),
            );
        } else {
            exchanges.truncate(4);
            exchanges[3] = Exchange::get(
                format!("/api/v1/namespaces/{TENANT}/pods"),
                list("Pod", vec![]),
            );
        }

        exchanges.extend(connector_termination(&record, true, true));
        exchanges.push(condition(
            &service,
            if namespace_revoked {
                "InvalidService"
            } else {
                "BackendNotVerified"
            },
            true,
        ));
        let (context, queue) = mock(exchanges);
        service_inner(&service, &context).await.unwrap();
        assert!(queue.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn connector_only_changes_persist_desired_state_and_resume_stopping_after_crash() {
    for rename in [false, true] {
        let (context, _) = mock(vec![]);
        let mut previous = record();
        previous.config_hash = publication_hash(&previous.publication, &context.resources).unwrap();
        previous.applied_hash = Some(previous.config_hash.clone());
        let mut service = service();

        if rename {
            service.spec.as_mut().unwrap().ports.as_mut().unwrap()[0].name = Some("renamed".into());
        } else {
            service.metadata.annotations = Some(BTreeMap::from([(
                "tunnellb.io/proxy-protocol".into(),
                "https=v2".into(),
            )]));
        }

        let mut desired = previous.clone();

        if rename {
            desired.publication.service.ports[0].name = "renamed".into();
        } else {
            desired.publication.service.ports[0].proxy_protocol = ProxyProtocol::V2;
        }

        desired.config_hash = publication_hash(&desired.publication, &context.resources).unwrap();
        desired.applied_hash = Some(desired.config_hash.clone());
        assert_ne!(desired.config_hash, previous.config_hash);
        let credentials = crate::transport::credentials(&previous.publication).unwrap();
        assert_eq!(
            crate::transport::server_config(&previous.publication, &credentials).unwrap(),
            crate::transport::server_config(&desired.publication, &credentials).unwrap(),
        );
        let deployment = crate::resources::connector_deployment(
            &previous.publication,
            &previous.backend_ports,
            &format!("client-{}", previous.publication.id),
            &context.resources,
            &previous.config_hash,
        );
        let machine = assigned_machine(&previous);
        let mut exchanges = ready_backend(&previous, &service, std::slice::from_ref(&machine));
        exchanges.extend(save_record(&previous, &desired, 200));
        exchanges.push(Exchange::get(
            path("deployments", &previous.publication.id),
            json!(deployment),
        ));
        exchanges.extend(connector_termination(&previous, true, true));
        exchanges.push(condition(&service, "Connecting", true));

        // Reconcile again using the saved desired hash but the old live template.
        // A restart between the save and delete must still terminate that template.
        exchanges.extend(ready_backend(&desired, &service, &[machine]));
        exchanges.push(Exchange::get(
            path("configmaps", &desired.publication.id),
            record_object(&desired),
        ));
        exchanges.push(Exchange::get(
            path("deployments", &desired.publication.id),
            json!(deployment),
        ));
        exchanges.extend(connector_termination(&desired, true, false));
        exchanges.push(condition(&service, "Connecting", true));
        // Losing backends after persisting desired state cannot mask the old
        // running template either.
        exchanges.extend(unavailable_backend(&desired, &[assigned_machine(&desired)]));
        exchanges.push(Exchange::get(
            path("deployments", &desired.publication.id),
            json!(deployment),
        ));
        exchanges.extend(connector_termination(&desired, true, false));
        exchanges.push(condition(&service, "BackendUnavailable", true));
        let (context, queue) = mock(exchanges);
        service_inner(&service, &context).await.unwrap();
        service_inner(&service, &context).await.unwrap();
        service_inner(&service, &context).await.unwrap();
        // No removal marker, lease mutation, credential replacement, or SSH job.
        assert!(queue.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn missing_deployment_does_not_recreate_connector_until_old_children_are_gone() {
    let mut record = record();
    let machine = assigned_machine(&record);
    let mut exchanges = vec![Exchange::reply(
        "GET",
        path("deployments", &record.publication.id),
        404,
        status(404),
    )];
    let mut terminating = connector_termination(&record, false, false);
    *terminating.last_mut().unwrap() = Exchange::get(
        path("replicasets", ""),
        list(
            "ReplicaSet",
            vec![json!({"metadata": {"name": "old-connector"}})],
        ),
    );
    exchanges.extend(terminating);
    let (context, queue) = mock(exchanges);
    assert!(
        !ensure_publication(&mut record, &machine, &context)
            .await
            .unwrap()
    );
    // No Secret change, replacement Deployment, or remote operation can race
    // children whose Deployment disappeared during foreground cleanup.
    assert!(queue.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unmanaged_service_without_finalizer_commits_removal_before_deleting_connector() {
    for write_status in [503, 200] {
        let record = record();
        let mut service = service();
        service.spec.as_mut().unwrap().type_ = Some("ClusterIP".into());
        service.spec.as_mut().unwrap().load_balancer_class = None;
        service.metadata.finalizers = None;
        let mut exchanges = vec![records(&record)];
        exchanges.extend(mark_removing(&record, write_status));

        if write_status == 200 {
            exchanges.extend(connector_termination(&record, true, true));
        }

        let (context, queue) = mock(exchanges);
        let result = service_inner(&service, &context).await;

        if write_status == 200 {
            result.unwrap();
        } else {
            assert!(matches!(
                result.unwrap_err().downcast_ref::<kube::Error>(),
                Some(kube::Error::Api(error)) if error.code == 503
            ));
        }

        // A failed commit must make no Deployment request; pending cleanup must
        // neither remove the record/lease nor need a Service finalizer.
        assert!(queue.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn persisted_removing_record_cannot_resume_apply_when_service_reverts() {
    let mut record = record();
    record.removing = true;
    let service = service();
    let mut exchanges = Vec::new();

    for _ in 0..2 {
        exchanges.push(records(&record));
        exchanges.extend(connector_termination(&record, true, false));
        let response = json!(service);
        exchanges.push(Exchange::inspect(
            "PATCH",
            format!("/api/v1/namespaces/{TENANT}/services/web/status"),
            200,
            move |body| {
                assert_eq!(body["status"]["conditions"][0]["reason"], "Reconfiguring");
                assert_eq!(body["status"]["conditions"][0]["status"], "False");
                assert!(body["status"].get("loadBalancer").is_none());
                response
            },
        ));
    }

    let (context, queue) = mock(exchanges);
    for _ in 0..2 {
        reconcile_service(Arc::new(service.clone()), context.clone())
            .await
            .unwrap();
    }

    // Also guard callers of ensure_publication itself, before even lease reads.
    let mut machine = Machine::new("edge", record.machine_spec.clone());
    machine.metadata.uid = Some(record.publication.machine_uid.clone());
    let error = ensure_publication(&mut record, &machine, &context)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("committed to removal"));
    assert!(queue.lock().unwrap().is_empty());
}

fn pending_remove_job(record: &PublicationRecord) -> Vec<Exchange> {
    let mut exchanges = Vec::new();

    for resource in ["jobs", "secrets", "networkpolicies"] {
        exchanges.push(Exchange::reply(
            "GET",
            path(resource, "job-*"),
            404,
            status(404),
        ));
    }

    exchanges.push(Exchange::get(path("jobs", ""), list("Job", vec![])));
    let saved = Arc::new(StdMutex::new(BTreeMap::<String, Value>::new()));
    for resource in ["secrets", "networkpolicies", "jobs"] {
        let saved = saved.clone();
        let publication = record.publication.clone();
        let generation = record.credential_generation.clone();
        exchanges.push(Exchange::inspect(
            "POST",
            path(resource, ""),
            201,
            move |mut body| {
                assert!(
                    body["metadata"]["ownerReferences"]
                        .as_array()
                        .is_none_or(Vec::is_empty)
                );

                if resource == "secrets" {
                    let secret: Secret = serde_json::from_value(body.clone()).unwrap();
                    let request: Request =
                        serde_json::from_slice(&secret.data.unwrap()["request.json"].0).unwrap();
                    assert_eq!(request.operation, Operation::Remove);
                    assert_eq!(request.publication, Some(publication));
                    assert_eq!(request.generation, generation);
                }

                body["metadata"]["uid"] = format!("{resource}-uid").into();
                body["metadata"]["resourceVersion"] = "10".into();
                saved.lock().unwrap().insert(resource.into(), body.clone());
                body
            },
        ));
    }

    for resource in ["secrets", "networkpolicies"] {
        let saved = saved.clone();
        exchanges.push(Exchange::inspect(
            "PATCH",
            path(resource, "job-*"),
            200,
            move |patch| {
                let mut body = saved.lock().unwrap().remove(resource).unwrap();
                body["metadata"]["ownerReferences"] = patch["metadata"]["ownerReferences"].clone();
                body["metadata"]["annotations"]
                    .as_object_mut()
                    .unwrap()
                    .extend(
                        patch["metadata"]["annotations"]
                            .as_object()
                            .unwrap()
                            .clone(),
                    );
                body
            },
        ));
    }

    exchanges
}

#[tokio::test]
async fn tenant_force_delete_detaches_but_keeps_remote_cleanup_and_port_lease() {
    let mut record = record();
    record.removing = true;
    let mut service = service();
    service.metadata.deletion_timestamp =
        Some(serde_json::from_value(json!("2026-01-01T00:00:00Z")).unwrap());
    service.metadata.annotations = Some(BTreeMap::from([(
        "tunnellb.io/force-delete".into(),
        "true".into(),
    )]));
    service
        .metadata
        .finalizers
        .as_mut()
        .unwrap()
        .push("other.example/cleanup".into());
    let pin_name = format!(
        "host-{}",
        &hex::encode(Sha256::digest(b"machine-uid"))[..20]
    );
    let pin = json!({
        "metadata": {
            "name": pin_name, "namespace": OPERATOR, "uid": "pin-uid", "resourceVersion": "4",
            "labels": {
                MANAGED_LABEL: "tunnellb", "tunnellb.io/kind": "host-pin",
                "tunnellb.io/machine-uid": "machine-uid",
            },
        },
        "immutable": true,
        "data": {"pin.json": ByteString(serde_json::to_vec(&json!({
            "known_hosts": "8.8.8.8 ssh-ed25519 synthetic-public-key",
            "fingerprint": "SHA256:synthetic-public-fingerprint",
            "address": "8.8.8.8", "ssh_port": 22,
        })).unwrap())},
    });
    let mut exchanges = vec![records(&record)];
    exchanges.extend(connector_termination(&record, false, false));
    exchanges.extend([
        Exchange::get(path("jobs", ""), list("Job", vec![])),
        Exchange::get(path("secrets", &pin_name), pin),
    ]);

    // A pending Job in the earlier list would bypass the abandon decision.
    // Require the actual Remove request to be created and remain pending.
    exchanges.extend(pending_remove_job(&record));
    exchanges.extend(connector_termination(&record, false, false));
    let response = json!(service);
    exchanges.push(Exchange::inspect(
        "PATCH",
        format!("/api/v1/namespaces/{TENANT}/services/web"),
        200,
        move |body| {
            assert_eq!(
                body["metadata"]["finalizers"],
                json!(["other.example/cleanup"])
            );
            assert_eq!(body["metadata"]["resourceVersion"], "11");
            response
        },
    ));

    let (context, queue) = mock(exchanges);
    service_inner(&service, &context).await.unwrap();
    // The strict sequence permits no ledger mutation, record deletion,
    // credential deletion, or abandonment of the remote Remove operation.
    assert!(queue.lock().unwrap().is_empty());
}

#[tokio::test]
async fn missing_record_allocation_recovery_propagates_api_errors_without_fallback() {
    for record_lookup_fails in [true, false] {
        let service = service();
        let record = record();
        let machine = assigned_machine(&record);
        let mut fallback = machine.clone();
        fallback.metadata.name = Some("z-fallback".into());
        fallback.metadata.uid = Some("fallback-uid".into());
        fallback.spec.address = "1.1.1.1".into();
        let mut exchanges = ready_backend(&record, &service, &[fallback, machine]);
        exchanges[0] = Exchange::get(path("configmaps", ""), list("ConfigMap", vec![]));
        exchanges.push(Exchange::reply(
            "GET",
            path("configmaps", &record.publication.id),
            if record_lookup_fails { 403 } else { 404 },
            status(if record_lookup_fails { 403 } else { 404 }),
        ));

        if !record_lookup_fails {
            let ledger_name = format!(
                "ports-{}",
                &hex::encode(Sha256::digest(b"machine-uid"))[..20]
            );
            exchanges.push(Exchange::reply(
                "GET",
                path("configmaps", &ledger_name),
                503,
                status(503),
            ));
        }

        let (context, queue) = mock(exchanges);
        let error = service_inner(&service, &context).await.unwrap_err();
        let expected_code = if record_lookup_fails { 403 } else { 503 };
        assert!(
            matches!(
                error.downcast_ref::<kube::Error>(),
                Some(kube::Error::Api(error)) if error.code == expected_code
            ),
            "{error:#}"
        );
        // The second eligible Machine must not hide operational failure by
        // accepting a new reservation or reporting AllocationPending.
        assert!(queue.lock().unwrap().is_empty());
    }
}
