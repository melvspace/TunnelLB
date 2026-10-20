use super::*;

#[tokio::test]
async fn all_deletes_use_object_uid_and_version_and_do_not_retry_conflicts() {
    for kind in ["publication", "allocation", "host-pin", "credentials"] {
        let (resource, object) = match kind {
            "publication" => ("configmaps", json!(record_object(&record(), "7"))),
            "allocation" => ("configmaps", json!(ledger_object(&Ledger::default(), "7"))),
            "host-pin" => ("secrets", json!(pin_object())),
            _ => ("secrets", json!(credential_object())),
        };
        let url = path(resource, object["metadata"]["name"].as_str().unwrap());
        let (store, queue) = mock(vec![
            Exchange::reply("GET", &url, 200, object),
            Exchange::inspect("DELETE", &url, 409, |body| {
                assert_eq!(body["preconditions"]["uid"], "kubernetes-object-uid");
                assert_eq!(body["preconditions"]["resourceVersion"], "7");
                status(409, "Conflict")
            }),
        ]);
        let result = match kind {
            "publication" => store.delete_record(ID).await,
            "allocation" => store.delete_ledger("server-uid").await,
            "host-pin" => store.delete_pin("server-uid").await,
            _ => store.delete_credentials(ID).await,
        };
        assert!(result.is_err());
        assert!(queue.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn ledger_deletion_requires_releasing_allocations_first() {
    let mut ledger = Ledger::default();
    ledger
        .allocate(ID, &record().publication.service, &server())
        .unwrap();
    let (store, queue) = mock(vec![Exchange::reply(
        "GET",
        &path("configmaps", &server_state_name("ports", "server-uid")),
        200,
        json!(ledger_object(&ledger, "1")),
    )]);
    assert!(store.delete_ledger("server-uid").await.is_err());
    assert!(queue.lock().unwrap().is_empty());
}

#[tokio::test]
async fn absent_cleanup_state_is_a_noop_and_delete_not_found_is_successful() {
    let ledger_url = path("configmaps", &server_state_name("ports", "server-uid"));
    let (store, queue) = mock(vec![
        Exchange::missing("GET", &ledger_url),
        Exchange::missing("GET", &ledger_url),
        Exchange::missing("GET", &ledger_url),
        Exchange::missing("GET", &path("configmaps", ID)),
        Exchange::missing(
            "GET",
            &path("secrets", &server_state_name("host", "server-uid")),
        ),
        Exchange::reply(
            "GET",
            &path("secrets", &format!("credentials-{ID}")),
            200,
            json!(credential_object()),
        ),
        Exchange::missing("DELETE", &path("secrets", &format!("credentials-{ID}"))),
    ]);
    store.release("server-uid", ID).await.unwrap();
    store
        .gc_allocations("server-uid", &BTreeSet::new())
        .await
        .unwrap();
    store.delete_ledger("server-uid").await.unwrap();
    store.delete_record(ID).await.unwrap();
    store.delete_pin("server-uid").await.unwrap();
    store.delete_credentials(ID).await.unwrap();
    assert!(queue.lock().unwrap().is_empty());
}
