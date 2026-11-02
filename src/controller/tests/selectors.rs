use super::*;
use crate::{controller::service::server_permitted, validation};

const REGION: &str = "topology.kubernetes.io/region";
const SELECTOR: &str = "tunnellb.io/server-selector";

fn regional_service() -> Service {
    let mut service = service();
    service.metadata.annotations = Some(BTreeMap::from([
        (SELECTOR.into(), format!("{REGION}=europe")),
        ("tunnellb.io/pool".into(), "minecraft".into()),
    ]));

    service
}

fn regional_server(record: &PublicationRecord) -> Server {
    let mut server = assigned_server(record);
    server.spec.pool = Some("minecraft".into());
    server.metadata.labels = Some(BTreeMap::from([(REGION.into(), "europe".into())]));

    server
}

#[test]
fn label_matches_do_not_bypass_namespace_or_pool_restrictions() {
    let record = record();
    let server = regional_server(&record);
    let service = regional_service();
    let namespace = serde_json::from_value(json!({
        "metadata": {"name": TENANT, "labels": {ENABLED_LABEL: "true"}},
    }))
    .unwrap();
    let request = validation::service_request(&service, &namespace).unwrap();

    assert!(server_permitted(&server, &request));

    let mut denied = server.clone();
    denied.spec.allowed_namespaces = vec!["other".into()];

    assert!(!server_permitted(&denied, &request));

    denied = server.clone();
    denied.spec.pool = Some("other".into());

    assert!(!server_permitted(&denied, &request));

    denied = server;
    denied.metadata.labels = None;

    assert!(!server_permitted(&denied, &request));
}

#[tokio::test]
async fn excluded_or_unready_servers_report_selector_shortfall_without_allocating() {
    for change in [
        "region",
        "missing-label",
        "namespace",
        "pool",
        "unready",
        "reserved-port",
    ] {
        let record = record();
        let service = regional_service();
        let mut server = regional_server(&record);

        match change {
            "region" => {
                server
                    .metadata
                    .labels
                    .as_mut()
                    .unwrap()
                    .insert(REGION.into(), "russia".into());
            }
            "missing-label" => server.metadata.labels = None,
            "namespace" => server.spec.allowed_namespaces = vec!["other".into()],
            "pool" => server.spec.pool = Some("other".into()),
            "unready" => server.status.as_mut().unwrap().phase = "Pending".into(),
            "reserved-port" => server.spec.reserved_ports = vec![443],
            _ => unreachable!(),
        }

        let mut exchanges = ready_backend(&record, &service, &[server]);
        exchanges[0] = Exchange::get(path("configmaps", ""), list("ConfigMap", vec![]));

        if change == "reserved-port" {
            let ledger_name = format!(
                "ports-{}",
                &hex::encode(Sha256::digest(record.publication.server_uid.as_bytes()))[..20],
            );
            exchanges.extend([
                Exchange::reply(
                    "GET",
                    path("configmaps", &record.publication.id),
                    404,
                    status(404),
                ),
                Exchange::reply("GET", path("configmaps", &ledger_name), 404, status(404)),
            ]);
        }

        exchanges.push(Exchange::inspect(
            "PATCH",
            format!("/api/v1/namespaces/{TENANT}/services/web/status"),
            200,
            |body| {
                let condition = &body["status"]["conditions"][0];
                assert_eq!(condition["reason"], "ServerSelectorUnsatisfied");
                assert!(condition["message"].as_str().unwrap().contains("0 of 1"));
                assert_eq!(body["status"]["loadBalancer"]["ingress"], json!([]));

                body
            },
        ));
        let (context, queue) = mock(exchanges);
        service_inner(&service, &context).await.unwrap();
        assert!(queue.lock().unwrap().is_empty(), "{change}");
    }
}

#[tokio::test]
async fn matching_assignments_survive_selector_and_unrelated_label_changes() {
    let record = record();
    let service = regional_service();
    let mut server = regional_server(&record);
    server
        .metadata
        .labels
        .as_mut()
        .unwrap()
        .insert("unrelated".into(), "changed".into());
    let mut exchanges = unavailable_backend(&record, &[server]);
    exchanges.push(Exchange::get(
        path("deployments", &record.publication.id),
        json!({"spec": {
            "selector": {},
            "template": {"metadata": {"annotations": {"tunnellb.io/config-hash": record.config_hash}}},
        }}),
    ));
    exchanges.push(condition(&service, "BackendUnavailable", true));
    let (context, queue) = mock(exchanges);
    service_inner(&service, &context).await.unwrap();
    assert!(queue.lock().unwrap().is_empty());
}

#[tokio::test]
async fn label_changes_revoke_excluded_assignments_before_replacement() {
    for region in [Some("russia"), None] {
        let mut record = record();
        let service = regional_service();
        record.publication.service.server_selector =
            Some(format!("{REGION}=europe").parse().unwrap());
        let mut server = regional_server(&record);
        server.metadata.labels =
            region.map(|value| BTreeMap::from([(REGION.into(), value.into())]));
        let mut exchanges = unavailable_backend(&record, &[server]);
        exchanges.extend(mark_removing(&record, 200));
        exchanges.extend(connector_termination(&record, true, true));
        exchanges.push(condition(&service, "Reconfiguring", false));
        let (context, queue) = mock(exchanges);
        service_inner(&service, &context).await.unwrap();
        assert!(queue.lock().unwrap().is_empty());
    }
}

#[test]
fn old_publication_records_default_to_unrestricted_server_labels() {
    let record = record();

    assert!(record.publication.service.server_selector.is_none());
    assert!(server_permitted(
        &regional_server(&record),
        &record.publication.service
    ));
}
