use super::*;

#[tokio::test]
async fn ledger_create_and_replace_races_preserve_concurrent_allocations() {
    let machine = machine();
    let request = record().publication.service;
    let mut competing = request.clone();
    competing.uid = "other-service".into();
    competing.name = "other".into();
    competing.ports[0].port = 8443;
    let mut winner = Ledger::default();
    let competing_control = winner.allocate(OTHER_ID, &competing, &machine).unwrap();
    let mut expected = winner.clone();
    let expected_control = expected.allocate(ID, &request, &machine).unwrap();
    let expected_value = serde_json::to_value(&expected).unwrap();
    let url = path("configmaps", &machine_state_name("ports", "machine-uid"));

    for existing in [false, true] {
        let expected_value = expected_value.clone();
        let (store, queue) = mock(vec![
            Exchange::reply(
                "GET",
                &url,
                if existing { 200 } else { 404 },
                if existing {
                    json!(ledger_object(&Ledger::default(), "1"))
                } else {
                    status(404, "NotFound")
                },
            ),
            Exchange::inspect(
                if existing { "PUT" } else { "POST" },
                &if existing {
                    url.clone()
                } else {
                    path("configmaps", "")
                },
                409,
                move |body| {
                    if existing {
                        assert_eq!(body["metadata"]["resourceVersion"], "1");
                    } else {
                        assert!(body["metadata"].get("resourceVersion").is_none());
                    }

                    status(
                        409,
                        if existing {
                            "Conflict"
                        } else {
                            "AlreadyExists"
                        },
                    )
                },
            ),
            Exchange::reply("GET", &url, 200, json!(ledger_object(&winner, "2"))),
            Exchange::inspect("PUT", &url, 200, move |body| {
                assert_eq!(body["metadata"]["resourceVersion"], "2");
                let ledger: Value =
                    serde_json::from_str(body["data"]["ledger.json"].as_str().unwrap()).unwrap();
                assert_eq!(ledger, expected_value);
                body
            }),
        ]);
        let allocated = store.allocate(&machine, &request, ID).await.unwrap();
        assert_eq!(allocated, expected_control);
        assert_ne!(allocated, competing_control);
        assert!(queue.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn conflicting_public_port_is_rejected_after_rereading_winner() {
    let machine = machine();
    let request = record().publication.service;
    let mut competing = request.clone();
    competing.uid = "other-service".into();
    let mut winner = Ledger::default();
    winner.allocate(OTHER_ID, &competing, &machine).unwrap();
    let url = path("configmaps", &machine_state_name("ports", "machine-uid"));
    let (store, queue) = mock(vec![
        Exchange::missing("GET", &url),
        Exchange::reply(
            "POST",
            &path("configmaps", ""),
            409,
            status(409, "AlreadyExists"),
        ),
        Exchange::reply("GET", &url, 200, json!(ledger_object(&winner, "2"))),
    ]);
    assert!(store.allocate(&machine, &request, ID).await.is_err());
    assert!(queue.lock().unwrap().is_empty());
}

#[tokio::test]
async fn ledger_retries_at_most_eight_times_and_can_succeed_on_eighth_attempt() {
    let url = path("configmaps", &machine_state_name("ports", "machine-uid"));

    for succeed in [false, true] {
        let mut exchanges = vec![];

        for attempt in 0..8 {
            exchanges.push(Exchange::missing("GET", &url));
            exchanges.push(if succeed && attempt == 7 {
                Exchange::inspect("POST", &path("configmaps", ""), 201, |body| body)
            } else {
                Exchange::reply(
                    "POST",
                    &path("configmaps", ""),
                    409,
                    status(409, "AlreadyExists"),
                )
            });
        }

        let (store, queue) = mock(exchanges);
        let result = store
            .allocate(&machine(), &record().publication.service, ID)
            .await;
        assert_eq!(result.is_ok(), succeed);

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

#[tokio::test]
async fn release_and_gc_reapply_removals_to_latest_ledger() {
    let machine = machine();
    let mut request = record().publication.service;
    let mut original = Ledger::default();
    original.allocate(ID, &request, &machine).unwrap();
    request.uid = "other-service".into();
    request.ports[0].port = 8443;
    original.allocate(OTHER_ID, &request, &machine).unwrap();
    let mut winner = original.clone();
    request.uid = "third-service".into();
    request.ports[0].port = 9443;
    winner.allocate(THIRD_ID, &request, &machine).unwrap();
    let url = path("configmaps", &machine_state_name("ports", "machine-uid"));

    for gc in [false, true] {
        let (store, queue) = mock(vec![
            Exchange::reply("GET", &url, 200, json!(ledger_object(&original, "1"))),
            Exchange::reply("PUT", &url, 409, status(409, "Conflict")),
            Exchange::reply("GET", &url, 200, json!(ledger_object(&winner, "2"))),
            Exchange::inspect("PUT", &url, 200, |body| {
                assert_eq!(body["metadata"]["resourceVersion"], "2");
                let ledger: Ledger =
                    serde_json::from_str(body["data"]["ledger.json"].as_str().unwrap()).unwrap();
                assert_eq!(
                    ledger
                        .publication_ids()
                        .into_iter()
                        .collect::<BTreeSet<_>>(),
                    BTreeSet::from([OTHER_ID.into(), THIRD_ID.into()])
                );
                body
            }),
        ]);

        if gc {
            store
                .gc_allocations(
                    "machine-uid",
                    &BTreeSet::from([OTHER_ID.into(), THIRD_ID.into()]),
                )
                .await
                .unwrap();
        } else {
            store.release("machine-uid", ID).await.unwrap();
        }

        assert!(queue.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn foreign_corrupt_or_unversioned_ledger_is_not_overwritten() {
    let url = path("configmaps", &machine_state_name("ports", "machine-uid"));

    for problem in ["foreign", "uid", "corrupt", "version"] {
        let mut object = ledger_object(&Ledger::default(), "1");
        match problem {
            "foreign" => object.metadata.labels = None,
            "uid" => {
                object
                    .metadata
                    .labels
                    .as_mut()
                    .unwrap()
                    .insert(MACHINE_UID_LABEL.into(), "other-machine".into());
            }

            "corrupt" => object.data = None,
            _ => object.metadata.resource_version = None,
        }

        let (store, queue) = mock(vec![Exchange::reply("GET", &url, 200, json!(object))]);
        assert!(
            store
                .allocate(&machine(), &record().publication.service, ID)
                .await
                .is_err()
        );
        assert!(queue.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn allocation_api_failures_do_not_allow_assignment_movement() {
    let url = path("configmaps", &machine_state_name("ports", "machine-uid"));

    for code in [403, 500] {
        let (store, queue) = mock(vec![
            Exchange::missing("GET", &url),
            Exchange::reply(
                "POST",
                &path("configmaps", ""),
                code,
                status(code, "Failure"),
            ),
        ]);
        let error = store
            .allocate(&machine(), &record().publication.service, ID)
            .await
            .unwrap_err();
        assert!(
            error
                .downcast_ref::<crate::allocation::AllocationConflict>()
                .is_none()
        );
        assert!(error.downcast_ref::<kube::Error>().is_some());
        assert!(queue.lock().unwrap().is_empty());
    }
}
