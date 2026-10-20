use super::*;

#[tokio::test]
async fn records_reject_foreign_or_corrupt_state() {
    for problem in [
        MANAGED_LABEL,
        KIND_LABEL,
        MACHINE_LABEL,
        MACHINE_UID_LABEL,
        SERVICE_UID_LABEL,
        PUBLICATION_LABEL,
        "namespace",
        "owner",
        "corrupt",
    ] {
        let mut object = json!(record_object(&record(), "1"));

        match problem {
            "namespace" => object["metadata"]["namespace"] = json!("application"),
            "owner" => {
                object["metadata"]["ownerReferences"] = json!([{
                    "apiVersion": "v1", "kind": "Service", "name": "web", "uid": "service-uid",
                }])
            }

            "corrupt" => object["data"]["record.json"] = json!("{"),
            label => {
                object["metadata"]["labels"]
                    .as_object_mut()
                    .unwrap()
                    .remove(label);
            }
        }

        let (store, queue) = mock(vec![Exchange::reply(
            "GET",
            &path("configmaps", ID),
            200,
            object,
        )]);
        assert!(store.get_record(ID).await.is_err(), "{problem}");
        assert!(queue.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn records_listing_does_not_silently_skip_corrupt_records() {
    let good = record_object(&record(), "1");
    let mut corrupt = good.clone();
    corrupt.data = None;
    let (store, queue) = mock(vec![Exchange::reply(
        "GET",
        &path("configmaps", ""),
        200,
        json!({"apiVersion": "v1", "kind": "ConfigMapList", "metadata": {}, "items": [good, corrupt]}),
    )]);
    assert!(store.records("").await.is_err());
    assert!(queue.lock().unwrap().is_empty());
}

#[tokio::test]
async fn record_conflict_reloads_resource_version_and_rechecks_owner() {
    for changed_owner in [None, Some(SERVICE_UID_LABEL), Some(MACHINE_UID_LABEL)] {
        let initial = record();
        let mut desired = initial.clone();
        desired.published = true;
        let mut winner = initial.clone();
        match changed_owner {
            Some(SERVICE_UID_LABEL) => winner.publication.service.uid = "new-service".into(),
            Some(MACHINE_UID_LABEL) => winner.publication.machine_uid = "new-machine".into(),
            _ => {}
        }

        let url = path("configmaps", ID);
        let mut exchanges = vec![
            Exchange::reply("GET", &url, 200, json!(record_object(&initial, "1"))),
            Exchange::inspect("PUT", &url, 409, |body| {
                assert_eq!(body["metadata"]["resourceVersion"], "1");
                status(409, "Conflict")
            }),
            Exchange::reply("GET", &url, 200, json!(record_object(&winner, "2"))),
        ];

        if changed_owner.is_none() {
            exchanges.push(Exchange::inspect("PUT", &url, 200, |body| {
                assert_eq!(body["metadata"]["resourceVersion"], "2");
                assert!(body["metadata"].get("ownerReferences").is_none());
                let stored: PublicationRecord =
                    serde_json::from_str(body["data"]["record.json"].as_str().unwrap()).unwrap();
                assert!(stored.published);
                body
            }));
        }

        let (store, queue) = mock(exchanges);
        assert_eq!(
            store.save_record(&desired).await.is_ok(),
            changed_owner.is_none()
        );
        assert!(queue.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn foreign_or_unversioned_record_is_never_overwritten_or_deleted() {
    for problem in ["foreign", "version", "uid"] {
        for deleting in [false, true] {
            if problem == "uid" && !deleting {
                continue;
            }

            let mut object = record_object(&record(), "1");
            match problem {
                "foreign" => object.metadata.labels = None,
                "version" => object.metadata.resource_version = None,
                _ => object.metadata.uid = None,
            }

            let (store, queue) = mock(vec![Exchange::reply(
                "GET",
                &path("configmaps", ID),
                200,
                json!(object),
            )]);
            let result = if deleting {
                store.delete_record(ID).await
            } else {
                let mut desired = record();
                desired.published = true;
                store.save_record(&desired).await
            };
            assert!(result.is_err());
            assert!(queue.lock().unwrap().is_empty());
        }
    }
}
