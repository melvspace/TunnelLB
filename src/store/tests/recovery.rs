use super::*;

#[tokio::test]
async fn unpublished_recovery_replaces_an_orphan_reservation_in_one_write() {
    let server = server();
    let mut request = record().publication.service;
    let mut orphan = Ledger::default();
    orphan.allocate(ID, &request, &server).unwrap();
    request.ports[0].port = 8443;
    let url = path("configmaps", &server_state_name("ports", "server-uid"));
    let (store, queue) = mock(vec![
        Exchange::missing("GET", &path("configmaps", ID)),
        Exchange::reply("GET", &url, 200, json!(ledger_object(&orphan, "1"))),
        Exchange::inspect("PUT", &url, 200, |body| {
            assert_eq!(body["metadata"]["resourceVersion"], "1");
            let ledger: Ledger =
                serde_json::from_str(body["data"]["ledger.json"].as_str().unwrap()).unwrap();
            assert_eq!(ledger.publication_ids(), vec![ID.to_string()]);
            assert_eq!(
                ledger.allocations[ID]
                    .ports
                    .iter()
                    .map(|p| p.port)
                    .collect::<Vec<_>>(),
                vec![8443]
            );
            body
        }),
    ]);
    assert_eq!(
        store
            .allocate_unpublished(&server, &request, ID)
            .await
            .unwrap(),
        20000
    );
    assert!(queue.lock().unwrap().is_empty());
}

#[test]
fn cleanup_state_defaults_for_old_records_and_survives_serialization() {
    let mut value = serde_json::to_value(record()).unwrap();
    value.as_object_mut().unwrap().remove("removing");
    value.as_object_mut().unwrap().remove("reserved");
    value
        .as_object_mut()
        .unwrap()
        .remove("credential_generation");
    let mut restored: PublicationRecord = serde_json::from_value(value).unwrap();
    assert!(!restored.removing);
    assert!(!restored.reserved);
    assert!(restored.credential_generation.is_none());
    restored.removing = true;
    restored.reserved = true;
    restored.credential_generation = Some("certificate-sha256".into());
    let reloaded: PublicationRecord =
        serde_json::from_str(&serde_json::to_string(&restored).unwrap()).unwrap();
    assert!(reloaded.removing);
    assert!(reloaded.reserved);
    assert_eq!(
        reloaded.credential_generation.as_deref(),
        Some("certificate-sha256")
    );
}

#[tokio::test]
async fn unpublished_allocation_refuses_any_record_and_propagates_record_lookup_errors() {
    for state in [
        "new",
        "published",
        "removing",
        "corrupt",
        "foreign",
        "forbidden",
    ] {
        let mut record = record();
        record.published = state == "published";
        record.removing = state == "removing";
        let mut object = record_object(&record, "1");

        if state == "corrupt" {
            object.data = None;
        } else if state == "foreign" {
            object.metadata.labels = None;
        }

        let (store, queue) = mock(vec![Exchange::reply(
            "GET",
            &path("configmaps", ID),
            if state == "forbidden" { 403 } else { 200 },
            if state == "forbidden" {
                status(403, "Forbidden")
            } else {
                json!(object)
            },
        )]);
        let error = store
            .allocate_unpublished(&server(), &record.publication.service, ID)
            .await
            .unwrap_err();
        assert!(
            error
                .downcast_ref::<crate::allocation::AllocationConflict>()
                .is_none()
        );
        assert!(queue.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn failed_unpublished_replacement_never_persists_a_release() {
    let server = server();
    let mut request = record().publication.service;
    let mut ledger = Ledger::default();
    ledger.allocate(ID, &request, &server).unwrap();
    let mut other = request.clone();
    other.uid = "other-service".into();
    other.ports[0].port = 8443;
    ledger.allocate(OTHER_ID, &other, &server).unwrap();
    request.ports[0].port = 8443;
    let (store, queue) = mock(vec![
        Exchange::missing("GET", &path("configmaps", ID)),
        Exchange::reply(
            "GET",
            &path("configmaps", &server_state_name("ports", "server-uid")),
            200,
            json!(ledger_object(&ledger, "1")),
        ),
    ]);
    let error = store
        .allocate_unpublished(&server, &request, ID)
        .await
        .unwrap_err();
    assert!(
        error
            .downcast_ref::<crate::allocation::AllocationConflict>()
            .is_some()
    );
    assert!(queue.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unpublished_cas_retry_rechecks_records_and_preserves_concurrent_reservations() {
    let server = server();
    let mut request = record().publication.service;
    let mut orphan = Ledger::default();
    orphan.allocate(ID, &request, &server).unwrap();
    let mut other = request.clone();
    other.uid = "other-service".into();
    other.ports[0].port = 9443;
    let mut winner = orphan.clone();
    winner.allocate(OTHER_ID, &other, &server).unwrap();
    request.ports[0].port = 8443;
    let url = path("configmaps", &server_state_name("ports", "server-uid"));

    for record_appears in [false, true] {
        let mut exchanges = vec![
            Exchange::missing("GET", &path("configmaps", ID)),
            Exchange::reply("GET", &url, 200, json!(ledger_object(&orphan, "1"))),
            Exchange::reply("PUT", &url, 409, status(409, "Conflict")),
            Exchange::reply(
                "GET",
                &path("configmaps", ID),
                if record_appears { 200 } else { 404 },
                if record_appears {
                    json!(record_object(&record(), "2"))
                } else {
                    status(404, "NotFound")
                },
            ),
        ];

        if !record_appears {
            exchanges.push(Exchange::reply(
                "GET",
                &url,
                200,
                json!(ledger_object(&winner, "2")),
            ));
            exchanges.push(Exchange::inspect("PUT", &url, 200, |body| {
                assert_eq!(body["metadata"]["resourceVersion"], "2");
                let ledger: Ledger =
                    serde_json::from_str(body["data"]["ledger.json"].as_str().unwrap()).unwrap();
                assert_eq!(
                    ledger.publication_ids(),
                    vec![ID.to_string(), OTHER_ID.to_string()]
                );
                assert_eq!(
                    ledger.allocations[ID].ports.iter().next().unwrap().port,
                    8443
                );
                assert_eq!(
                    ledger.allocations[OTHER_ID]
                        .ports
                        .iter()
                        .next()
                        .unwrap()
                        .port,
                    9443
                );
                body
            }));
        }

        let (store, queue) = mock(exchanges);
        let result = store.allocate_unpublished(&server, &request, ID).await;
        assert_eq!(result.is_err(), record_appears);

        if let Err(error) = result {
            assert!(
                error
                    .downcast_ref::<crate::allocation::AllocationConflict>()
                    .is_none()
            );
        }

        assert!(queue.lock().unwrap().is_empty());
    }
}
