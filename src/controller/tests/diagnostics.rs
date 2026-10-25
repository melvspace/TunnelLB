use super::*;
use crate::{allocation::Ledger, controller::server::reconcile_server, provision::Diagnostic};

const INSPECTION: &str = "SSH Job retry limit exceeded; Could not inspect UFW state; reconciliation will retry. Check that UFW is functional.";
const CLEANUP: &str = "SSH Job retry limit exceeded; Could not remove TunnelLB's owned UFW rules; cleanup will retry and port claims remain reserved. Check UFW and TunnelLB's owned application profiles.";
const GENERIC_WORKER: &str = "SSH Job retry limit exceeded; worker reported a provisioning error";

fn pin(record: &PublicationRecord) -> Exchange {
    let publication = &record.publication;
    let name = format!(
        "host-{}",
        &hex::encode(Sha256::digest(publication.server_uid.as_bytes()))[..20]
    );
    Exchange::get(
        path("secrets", &name),
        json!({
            "metadata": {
                "name": name, "namespace": OPERATOR,
                "labels": {
                    MANAGED_LABEL: "tunnellb", "tunnellb.io/kind": "host-pin",
                    "tunnellb.io/server-uid": publication.server_uid,
                },
            },
            "immutable": true,
            "data": {"pin.json": ByteString(serde_json::to_vec(&json!({
                "known_hosts": format!("{} ssh-ed25519 synthetic-public-key", publication.server_address),
                "fingerprint": "SHA256:synthetic-public-fingerprint",
                "address": publication.server_address, "ssh_port": 22,
            })).unwrap())},
        }),
    )
}

fn ledger(record: &PublicationRecord) -> Exchange {
    let publication = &record.publication;
    let mut server = assigned_server(record);
    server.metadata.name = Some(publication.server_name.clone());
    let mut ledger = Ledger::default();
    ledger
        .allocate(&publication.id, &publication.service, &server)
        .unwrap();
    let name = format!(
        "ports-{}",
        &hex::encode(Sha256::digest(publication.server_uid.as_bytes()))[..20]
    );
    Exchange::get(
        path("configmaps", &name),
        json!({
            "metadata": {
                "name": name, "namespace": OPERATOR, "resourceVersion": "3",
                "labels": {
                    MANAGED_LABEL: "tunnellb", "tunnellb.io/kind": "allocation",
                    "tunnellb.io/server-uid": publication.server_uid,
                },
            },
            "data": {"ledger.json": serde_json::to_string(&ledger).unwrap()},
        }),
    )
}

fn credentials(record: &PublicationRecord) -> Exchange {
    let mut metadata = record_object(record)["metadata"].clone();
    metadata["name"] = format!("credentials-{}", record.publication.id).into();
    metadata["labels"]["tunnellb.io/kind"] = "credentials".into();
    Exchange::get(
        path("secrets", metadata["name"].as_str().unwrap()),
        json!({
            "metadata": metadata, "immutable": true,
            "data": {
                "token": ByteString("a".repeat(64).into_bytes()),
                "tls.crt": ByteString(b"synthetic-certificate".to_vec()),
                "tls.key": ByteString(b"REMOTE_SECRET_SENTINEL".to_vec()),
            },
        }),
    )
}

fn publication_reads(record: &PublicationRecord, ready: bool) -> Vec<Exchange> {
    let mut exchanges = vec![Exchange::get(
        path("configmaps", &record.publication.id),
        record_object(record),
    )];

    if record.reserved {
        exchanges.push(Exchange::get(
            path("deployments", &record.publication.id),
            json!({
                "spec": {
                    "selector": {},
                    "template": {"metadata": {"annotations": {"tunnellb.io/config-hash": record.config_hash}}},
                },
                "status": {"availableReplicas": if ready { 1 } else { 0 }, "updatedReplicas": 1},
            }),
        ));
    } else {
        exchanges.push(Exchange::reply(
            "GET",
            path("deployments", &record.publication.id),
            404,
            status(404),
        ));
        exchanges.extend(connector_termination(record, false, false));
    }

    exchanges.extend([ledger(record), pin(record), credentials(record)]);
    exchanges
}

fn healthy_connector(record: &PublicationRecord) -> Vec<Exchange> {
    let id = &record.publication.id;
    let mut exchanges = Vec::new();

    for (resource, name) in [
        ("secrets", format!("client-{id}")),
        ("networkpolicies", id.clone()),
        ("deployments", id.clone()),
    ] {
        let existing = json!({"metadata": {
            "name": name, "namespace": OPERATOR, "resourceVersion": "9",
            "labels": {
                MANAGED_LABEL: "tunnellb", PUBLICATION_LABEL: id,
                SERVER_LABEL: record.publication.server_name,
                SERVICE_UID_LABEL: record.publication.service.uid,
                "tunnellb.io/service-namespace": record.publication.service.namespace,
                "tunnellb.io/service-name": record.publication.service.name,
            },
        }});
        exchanges.push(Exchange::get(path(resource, &name), existing));
        exchanges.push(Exchange::inspect(
            "PATCH",
            path(resource, &name),
            200,
            |body| body,
        ));
    }

    exchanges.extend([
        Exchange::get(
            path("deployments", id),
            json!({"status": {"availableReplicas": 1, "updatedReplicas": 1}}),
        ),
        Exchange::get(path("configmaps", id), record_object(record)),
    ]);
    exchanges
}

fn service_failure(
    service: &Service,
    reason: &'static str,
    message: &'static str,
    ingress: Option<Vec<&'static str>>,
) -> Exchange {
    let response = json!(service);
    Exchange::inspect(
        "PATCH",
        format!("/api/v1/namespaces/{TENANT}/services/web/status"),
        200,
        move |body| {
            let condition = &body["status"]["conditions"][0];
            assert_eq!(condition["type"], "TunnelLBReady");
            assert_eq!(condition["status"], "False");
            assert_eq!(condition["reason"], reason);
            assert_eq!(condition["message"], message);
            assert_eq!(condition["observedGeneration"], 2);
            assert!(!body.to_string().contains("SECRET_SENTINEL"));

            if let Some(ips) = ingress {
                assert_eq!(
                    body["status"]["loadBalancer"]["ingress"],
                    json!(
                        ips.into_iter()
                            .map(|ip| json!({"ip": ip, "ipMode": "Proxy"}))
                            .collect::<Vec<_>>()
                    )
                );
            } else {
                assert!(body["status"].get("loadBalancer").is_none());
            }

            response
        },
    )
}

#[tokio::test]
async fn failed_apply_or_reserve_reports_diagnostics_and_reconciles_remaining_publications() {
    for (operation, already_applied, error, reason, message) in [
        (
            Operation::Apply,
            true,
            r#"{"error":"control-unreachable"}"#,
            "ControlUnreachable",
            "SSH Job retry limit exceeded; The worker could not reach the publication's TCP control port within 5 seconds after Apply. Check the Server address, control port, host/provider firewalls and cluster egress; connector readiness is still required.",
        ),
        (
            Operation::Reserve,
            false,
            r#"{"error":"firewall-inspection"}"#,
            "FirewallInspectionFailed",
            INSPECTION,
        ),
        (
            Operation::Apply,
            true,
            r#"{"error":"REMOTE_SECRET_SENTINEL"}"#,
            "SSHFailed",
            GENERIC_WORKER,
        ),
        (
            Operation::Apply,
            false,
            r#"{"error":"firewall-inspection"}"#,
            "FirewallInspectionFailed",
            INSPECTION,
        ),
    ] {
        let (context, _) = mock(vec![]);
        let mut failed = record();
        failed.publication.service.replicas = 2;
        failed.config_hash = publication_hash(&failed.publication, &context.resources).unwrap();
        failed.applied_hash = Some(failed.config_hash.clone());
        failed.credential_generation = Some(crate::transport::credential_generation(
            "synthetic-certificate",
        ));
        let mut healthy = failed.clone();
        healthy.publication.server_name = "edge-other".into();
        healthy.publication.server_uid = "other-server-uid".into();
        healthy.publication.server_address = "1.1.1.1".parse().unwrap();
        healthy.publication.id = publication_id("service-uid", "other-server-uid");
        healthy.server_spec.address = "1.1.1.1".into();
        healthy.config_hash = publication_hash(&healthy.publication, &context.resources).unwrap();
        healthy.applied_hash = Some(healthy.config_hash.clone());

        if !already_applied {
            failed.applied_hash = None;
            failed.published = false;
        }

        if operation == Operation::Reserve {
            failed.reserved = false;
        }

        let mut service = service();
        service.metadata.annotations = Some(BTreeMap::from([(
            "tunnellb.io/replicas".into(),
            "2".into(),
        )]));
        let ingress = if failed.published {
            vec!["1.1.1.1", "8.8.8.8"]
        } else {
            vec!["1.1.1.1"]
        };
        service.status.as_mut().unwrap().load_balancer = Some(
            serde_json::from_value(json!({"ingress": ingress.iter()
                .map(|ip| json!({"ip": ip, "ipMode": "Proxy"})).collect::<Vec<_>>()}))
            .unwrap(),
        );
        let mut other_server = assigned_server(&healthy);
        other_server.metadata.name = Some(healthy.publication.server_name.clone());
        let mut exchanges =
            ready_backend(&failed, &service, &[assigned_server(&failed), other_server]);
        exchanges[0] = Exchange::get(
            path("configmaps", ""),
            list(
                "ConfigMap",
                vec![record_object(&failed), record_object(&healthy)],
            ),
        );
        exchanges.extend(publication_reads(&failed, false));

        if operation == Operation::Reserve {
            exchanges.push(ledger(&failed));
        }

        exchanges.extend(worker_job(operation, Some(&failed), Some(error)));

        if already_applied {
            // Failed remote repairs still refresh the local Secret, policy and
            // Deployment. An initial Apply failure must not start a connector.
            exchanges.extend(healthy_connector(&failed));
        }

        exchanges.extend(publication_reads(&healthy, true));
        exchanges.extend(worker_job(
            Operation::Apply,
            Some(&healthy),
            None,
        ));
        exchanges.extend(healthy_connector(&healthy));
        exchanges.push(service_failure(&service, reason, message, Some(ingress)));
        let (context, queue) = mock(exchanges);
        reconcile_service(Arc::new(service), context).await.unwrap();
        // The second connector is updated despite the first worker failure.
        assert!(queue.lock().unwrap().is_empty());
    }
}

fn server() -> Server {
    let mut server = assigned_server(&record());
    server.metadata.finalizers = Some(vec![FINALIZER.into()]);
    server.metadata.resource_version = Some("11".into());
    server.metadata.generation = Some(2);
    server.status.as_mut().unwrap().enrolled_revision = Some("old-revision".into());
    server
}

fn server_failure(server: &Server, reason: &'static str, message: String) -> Exchange {
    let response = json!(server);
    let phase = if server.metadata.deletion_timestamp.is_some() {
        "Deleting"
    } else {
        "Degraded"
    };
    Exchange::inspect(
        "PATCH",
        "/apis/tunnellb.io/v1alpha1/servers/edge/status".into(),
        200,
        move |body| {
            assert_eq!(
                body["status"],
                json!({
                    "phase": phase, "reason": reason, "message": message,
                    "enrolledRevision": "old-revision", "observedGeneration": 2,
                })
            );
            assert!(!body.to_string().contains("SECRET_SENTINEL"));
            response
        },
    )
}

fn enrollment(server: &Server) -> Vec<Exchange> {
    vec![
        Exchange::get("/api/v1/nodes".into(), list("Node", vec![])),
        Exchange::get(
            "/apis/tunnellb.io/v1alpha1/servers".into(),
            list("Server", vec![json!(server)]),
        ),
        pin(&record()),
    ]
}

#[tokio::test]
async fn enrollment_and_uninstall_keep_worker_diagnostics_and_server_phase() {
    for (operation, error, reason, message) in [
        (
            Operation::Enroll,
            r#"{"error":"ssh-authentication"}"#,
            "SSHFailed",
            format!("SSH Job retry limit exceeded; {}", Diagnostic::SshAuthentication),
        ),
        (
            Operation::Enroll,
            r#"{"error":"sudo"}"#,
            "SSHFailed",
            format!("SSH Job retry limit exceeded; {}", Diagnostic::RemoteSudo),
        ),
        (
            Operation::Enroll,
            r#"{"error":"firewall-configuration"}"#,
            "FirewallConfigurationFailed",
            "SSH Job retry limit exceeded; Could not configure TunnelLB's UFW rules; reconciliation will retry. Check UFW and TunnelLB's owned application profiles.".into(),
        ),
        (Operation::Uninstall, r#"{"error":"firewall-cleanup"}"#, "FirewallCleanupFailed", CLEANUP.into()),
        (
            Operation::Uninstall,
            r#"{"error":"firewall-unavailable"}"#,
            "FirewallUnavailable",
            format!("SSH Job retry limit exceeded; {}", Diagnostic::FirewallUnavailable),
        ),
    ] {
        let mut server = server();
        let mut exchanges = if operation == Operation::Uninstall {
            server.metadata.deletion_timestamp =
                Some(serde_json::from_value(json!("2026-01-01T00:00:00Z")).unwrap());
            vec![
                Exchange::get(path("configmaps", ""), list("ConfigMap", vec![])),
                Exchange::get(path("jobs", ""), list("Job", vec![])),
                pin(&record()),
            ]
        } else {
            enrollment(&server)
        };
        exchanges.extend(worker_job(operation, None, Some(error)));
        exchanges.push(server_failure(&server, reason, message));
        let (context, queue) = mock(exchanges);
        let result = reconcile_server(Arc::new(server), context).await;
        assert_eq!(result.is_err(), operation == Operation::Uninstall);
        // Failed uninstall retains the pin, ledger and finalizer.
        assert!(queue.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn arbitrary_remote_errors_cannot_become_server_diagnostics() {
    for error in [
        r#"{"error":"REMOTE_SECRET_SENTINEL"}"#,
        r#"{"error":"firewall-inspection","message":"REMOTE_SECRET_SENTINEL"}"#,
        r#"{"error":"SSH worker failed"}"#,
    ] {
        let server = server();
        let mut exchanges = enrollment(&server);
        exchanges.extend(worker_job(Operation::Enroll, None, Some(error)));
        exchanges.push(server_failure(&server, "SSHFailed", GENERIC_WORKER.into()));
        let (context, queue) = mock(exchanges);
        reconcile_server(Arc::new(server), context).await.unwrap();
        assert!(queue.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn api_error_text_cannot_become_service_or_server_diagnostics() {
    let mut failure = status(503);
    failure["message"] = "firewall-inspection API_SECRET_SENTINEL".into();
    failure["reason"] = "FirewallInspectionFailed".into();
    let service = service();
    let (context, queue) = mock(vec![
        Exchange::reply("GET", path("configmaps", ""), 503, failure.clone()),
        service_failure(
            &service,
            "ReconcileFailed",
            "Operation failed and will retry; check Server and SSH Job state.",
            None,
        ),
    ]);
    assert!(reconcile_service(Arc::new(service), context).await.is_err());
    assert!(queue.lock().unwrap().is_empty());

    let server = server();
    let (context, queue) = mock(vec![
        Exchange::reply("GET", "/api/v1/nodes".into(), 503, failure),
        server_failure(
            &server,
            "ReconcileFailed",
            "Operation failed; inspect SSH Job state and configuration. Credentials are never included in errors.".into(),
        ),
    ]);
    assert!(reconcile_server(Arc::new(server), context).await.is_err());
    assert!(queue.lock().unwrap().is_empty());
}

#[tokio::test]
async fn failed_remove_keeps_cleanup_pending_but_allows_tenant_force_delete() {
    for force_delete in [false, true] {
        let mut record = record();
        record.removing = true;
        let mut service = service();
        service.metadata.deletion_timestamp =
            Some(serde_json::from_value(json!("2026-01-01T00:00:00Z")).unwrap());
        service
            .metadata
            .finalizers
            .as_mut()
            .unwrap()
            .push("other.example/cleanup".into());

        if force_delete {
            service.metadata.annotations = Some(BTreeMap::from([(
                "tunnellb.io/force-delete".into(),
                "true".into(),
            )]));
        }

        let mut exchanges = vec![records(&record)];
        exchanges.extend(connector_termination(&record, false, false));
        exchanges.extend([
            Exchange::get(path("jobs", ""), list("Job", vec![])),
            pin(&record),
        ]);
        exchanges.extend(worker_job(
            Operation::Remove,
            Some(&record),
            Some(r#"{"error":"firewall-cleanup"}"#),
        ));

        if force_delete {
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
        } else {
            exchanges.push(service_failure(
                &service,
                "FirewallCleanupFailed",
                CLEANUP,
                None,
            ));
        }

        let (context, queue) = mock(exchanges);
        let result = reconcile_service(Arc::new(service), context).await;
        assert_eq!(result.is_ok(), force_delete);
        // Neither path may release the port lease or discard remote cleanup state.
        assert!(queue.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn healthy_publications_reconcile_remote_rules_and_preserve_connectors_on_failure() {
    for failure in [None, Some(r#"{"error":"firewall-inspection"}"#)] {
        let (context, _) = mock(vec![]);
        let mut record = record();
        record.config_hash = publication_hash(&record.publication, &context.resources).unwrap();
        record.applied_hash = Some(record.config_hash.clone());
        record.credential_generation = Some(crate::transport::credential_generation(
            "synthetic-certificate",
        ));
        let server = assigned_server(&record);
        let mut exchanges = publication_reads(&record, true);
        exchanges.remove(0);
        exchanges.extend(worker_job(
            Operation::Apply,
            Some(&record),
            failure,
        ));
        exchanges.extend(healthy_connector(&record));
        let (context, queue) = mock(exchanges);
        let result = ensure_publication(&mut record, &server, &context).await;

        if failure.is_some() {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Could not inspect UFW")
            );
        } else {
            assert!(result.unwrap());
        }

        assert!(record.published);
        assert!(queue.lock().unwrap().is_empty());
    }
}
