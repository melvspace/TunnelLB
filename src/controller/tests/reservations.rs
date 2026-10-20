use super::*;
use crate::{allocation::Ledger, controller::reservation::commit_reservation};

fn ledger_object(record: &PublicationRecord, control: u16) -> Value {
    let server = assigned_server(record);
    let publication = &record.publication;
    let mut ledger = Ledger::default();
    ledger
        .allocate(&publication.id, &publication.service, &server)
        .unwrap();
    ledger
        .allocations
        .get_mut(&publication.id)
        .unwrap()
        .control_port = control;
    let name = format!(
        "ports-{}",
        &hex::encode(Sha256::digest(publication.server_uid.as_bytes()))[..20]
    );

    json!({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {
            "name": name, "namespace": OPERATOR, "uid": "ledger-uid", "resourceVersion": "3",
            "labels": {
                MANAGED_LABEL: "tunnellb", "tunnellb.io/kind": "allocation",
                "tunnellb.io/server-uid": publication.server_uid,
            },
        },
        "data": {"ledger.json": serde_json::to_string(&ledger).unwrap()},
    })
}

#[tokio::test]
async fn remote_control_commit_recovers_after_record_write_failure_before_any_apply() {
    let (context, _) = mock(vec![]);
    let mut provisional = record();
    provisional.published = false;
    provisional.applied_hash = None;
    provisional.reserved = false;
    provisional.config_hash =
        publication_hash(&provisional.publication, &context.resources).unwrap();
    let server = assigned_server(&provisional);
    let selected = provisional.publication.control_port + 1;
    let ledger = ledger_object(&provisional, provisional.publication.control_port);
    let confirmed = ledger_object(&provisional, selected);
    let ledger_path = path("configmaps", ledger["metadata"]["name"].as_str().unwrap());
    let mut committed = provisional.clone();
    committed.publication.control_port = selected;
    committed.config_hash = publication_hash(&committed.publication, &context.resources).unwrap();
    committed.reserved = true;
    let expected_ledger = confirmed.clone();
    let mut exchanges = vec![
        Exchange::get(ledger_path.clone(), ledger),
        Exchange::inspect("PUT", ledger_path.clone(), 200, move |body| {
            assert_eq!(body, expected_ledger);
            body
        }),
    ];
    exchanges.extend(save_record(&provisional, &committed, 503));

    // Restart with only the ledger write persisted. Recovery must save the
    // selected port, then repeat Reserve; it cannot infer permission to Apply.
    exchanges.push(Exchange::reply(
        "GET",
        path("deployments", &provisional.publication.id),
        404,
        status(404),
    ));
    exchanges.extend(connector_termination(&provisional, false, false));
    exchanges.push(Exchange::get(ledger_path.clone(), confirmed.clone()));
    let mut recovered = committed.clone();
    recovered.reserved = false;
    exchanges.extend(save_record(&provisional, &recovered, 200));

    // Repeating the successful remote answer needs no second ledger mutation.
    exchanges.push(Exchange::get(ledger_path, confirmed));
    exchanges.extend(save_record(&recovered, &committed, 200));
    let (context, queue) = mock(exchanges);
    assert!(
        commit_reservation(&mut provisional.clone(), &server, selected, &context)
            .await
            .is_err()
    );
    assert!(
        !ensure_publication(&mut provisional, &server, &context)
            .await
            .unwrap()
    );
    assert!(!provisional.reserved);
    assert_eq!(provisional.publication.control_port, selected);
    commit_reservation(&mut provisional, &server, selected, &context)
        .await
        .unwrap();
    assert!(provisional.reserved);
    assert_eq!(provisional.config_hash, committed.config_hash);
    assert!(queue.lock().unwrap().is_empty());
}

#[tokio::test]
async fn remote_answer_cannot_move_an_applied_publication_control_port() {
    let mut record = record();
    let server = assigned_server(&record);
    let selected = record.publication.control_port + 1;
    let (context, queue) = mock(vec![]);
    assert!(
        commit_reservation(&mut record, &server, selected, &context)
            .await
            .is_err()
    );
    assert!(queue.lock().unwrap().is_empty());
}
