use super::*;

fn allocated_ledger() -> Ledger {
    let mut ledger = Ledger::default();
    ledger
        .allocate(ID, &record().publication.service, &machine())
        .unwrap();
    ledger
}

#[tokio::test]
async fn control_confirmation_retries_cas_preserving_concurrent_leases_and_metadata() {
    let machine = machine();
    let publication = record().publication;
    let original = allocated_ledger();
    let mut winner = original.clone();
    let mut competing = publication.service.clone();
    competing.uid = "other-service".into();
    competing.ports[0].port = 8443;
    winner.allocate(OTHER_ID, &competing, &machine).unwrap();
    let mut expected = winner.clone();
    expected.allocations.get_mut(ID).unwrap().control_port = 20003;
    let mut winner_object = ledger_object(&winner, "2");
    winner_object
        .data
        .as_mut()
        .unwrap()
        .insert("unrelated".into(), "preserved".into());
    let url = path("configmaps", &machine_state_name("ports", "machine-uid"));
    let (store, queue) = mock(vec![
        Exchange::reply("GET", &url, 200, json!(ledger_object(&original, "1"))),
        Exchange::inspect("PUT", &url, 409, |body| {
            assert_eq!(body["metadata"]["resourceVersion"], "1");
            status(409, "Conflict")
        }),
        Exchange::reply("GET", &url, 200, json!(winner_object)),
        Exchange::inspect("PUT", &url, 200, move |body| {
            assert_eq!(body["metadata"]["resourceVersion"], "2");
            assert_eq!(body["data"]["unrelated"], "preserved");
            let actual: Ledger =
                serde_json::from_str(body["data"]["ledger.json"].as_str().unwrap()).unwrap();
            assert_eq!(actual, expected);
            body
        }),
    ]);
    store
        .confirm_control(&machine, &publication, 20003)
        .await
        .unwrap();
    assert!(queue.lock().unwrap().is_empty());
}

#[tokio::test]
async fn control_confirmation_revalidates_conflicts_or_observes_its_success_after_cas_retry() {
    let machine = machine();
    let publication = record().publication;
    let original = allocated_ledger();
    let url = path("configmaps", &machine_state_name("ports", "machine-uid"));

    for change in ["selected", "third-control", "owner", "public", "collision"] {
        let mut winner = original.clone();
        let allocation = winner.allocations.get_mut(ID).unwrap();
        match change {
            "selected" => allocation.control_port = 20003,
            "third-control" => allocation.control_port = 20002,
            "owner" => allocation.service_uid = "recreated-service".into(),
            "public" => {
                allocation.ports = BTreeSet::from([crate::allocation::PortReservation {
                    protocol: Protocol::Udp,
                    port: 443,
                }]);
            }
            _ => {
                let mut competing = publication.service.clone();
                competing.uid = "other-service".into();
                competing.ports[0].port = 20003;
                winner.allocate(OTHER_ID, &competing, &machine).unwrap();
            }
        }

        let (store, queue) = mock(vec![
            Exchange::reply("GET", &url, 200, json!(ledger_object(&original, "1"))),
            Exchange::reply("PUT", &url, 409, status(409, "Conflict")),
            Exchange::reply("GET", &url, 200, json!(ledger_object(&winner, "2"))),
        ]);
        let result = store.confirm_control(&machine, &publication, 20003).await;
        assert_eq!(result.is_ok(), change == "selected", "{change}");
        assert!(queue.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn control_exclusions_read_the_owned_ledger_without_requiring_old_control_equality() {
    let machine = machine();
    let publication = record().publication;
    let mut ledger = allocated_ledger();
    ledger.allocations.get_mut(ID).unwrap().control_port = 20003;
    let mut other = publication.service.clone();
    other.uid = "other-service".into();
    other.ports[0].port = 8443;
    ledger.allocate(OTHER_ID, &other, &machine).unwrap();
    let (store, queue) = mock(vec![Exchange::reply(
        "GET",
        &path("configmaps", &machine_state_name("ports", "machine-uid")),
        200,
        json!(ledger_object(&ledger, "1")),
    )]);
    assert_eq!(
        store
            .control_exclusions(&machine, &publication)
            .await
            .unwrap(),
        vec![22, 443, 8443, 20000]
    );
    assert!(queue.lock().unwrap().is_empty());
}

#[tokio::test]
async fn control_operations_reject_missing_foreign_or_invalid_ledger_without_writes() {
    let machine = machine();
    let publication = record().publication;
    let url = path("configmaps", &machine_state_name("ports", "machine-uid"));

    for problem in [
        "missing-ledger",
        "missing-lease",
        "foreign",
        "machine-uid",
        "version",
        "corrupt",
        "invalid",
    ] {
        let mut ledger = allocated_ledger();

        if problem == "missing-lease" {
            ledger.release(ID);
        } else if problem == "invalid" {
            ledger.allocations.get_mut(ID).unwrap().control_port = 0;
        }

        let mut object = ledger_object(&ledger, "1");
        match problem {
            "foreign" => object.metadata.labels = None,
            "machine-uid" => {
                object
                    .metadata
                    .labels
                    .as_mut()
                    .unwrap()
                    .insert(MACHINE_UID_LABEL.into(), "recreated-machine".into());
            }
            "version" => object.metadata.resource_version = None,
            "corrupt" => object.data = None,
            _ => {}
        }

        for confirm in [false, true] {
            let (store, queue) = mock(vec![if problem == "missing-ledger" {
                Exchange::missing("GET", &url)
            } else {
                Exchange::reply("GET", &url, 200, json!(object))
            }]);

            if confirm {
                assert!(
                    store
                        .confirm_control(&machine, &publication, 20003)
                        .await
                        .is_err(),
                    "{problem}"
                );
            } else {
                assert!(
                    store
                        .control_exclusions(&machine, &publication)
                        .await
                        .is_err(),
                    "{problem}"
                );
            }

            assert!(queue.lock().unwrap().is_empty());
        }
    }
}
