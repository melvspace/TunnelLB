use super::*;

#[tokio::test]
async fn credential_creation_returns_persisted_winner_without_rotation() {
    let url = path("secrets", &format!("credentials-{ID}"));

    for conflict in [false, true] {
        let mut exchanges = vec![
            Exchange::missing("GET", &url),
            Exchange::reply(
                "POST",
                &path("secrets", ""),
                if conflict { 409 } else { 201 },
                if conflict {
                    status(409, "AlreadyExists")
                } else {
                    json!(credential_object())
                },
            ),
        ];

        if conflict {
            exchanges.push(Exchange::reply(
                "GET",
                &url,
                200,
                json!(credential_object()),
            ));
        }

        exchanges.push(Exchange::reply(
            "GET",
            &url,
            200,
            json!(credential_object()),
        ));
        let (store, queue) = mock(exchanges);

        for _ in 0..2 {
            let credentials = store.credentials(&record().publication).await.unwrap();
            assert_eq!(credentials.token, "persisted-token");
            assert_eq!(credentials.certificate_pem, "persisted-certificate");
            assert_eq!(credentials.private_key_pem, "persisted-private-key");
        }

        assert!(queue.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn credentials_reject_foreign_and_incomplete_existing_secrets() {
    for problem in [
        SERVICE_UID_LABEL,
        SERVER_UID_LABEL,
        MANAGED_LABEL,
        "tls.key",
        "mutable",
    ] {
        let mut secret = credential_object();
        match problem {
            "tls.key" => {
                secret.data.as_mut().unwrap().remove(problem);
            }

            "mutable" => secret.immutable = Some(false),
            key => {
                secret
                    .metadata
                    .labels
                    .as_mut()
                    .unwrap()
                    .insert(key.into(), "other".into());
            }
        }

        let (store, queue) = mock(vec![Exchange::reply(
            "GET",
            &path("secrets", &format!("credentials-{ID}")),
            200,
            json!(secret),
        )]);
        assert!(
            store.credentials(&record().publication).await.is_err(),
            "{problem}"
        );
        assert!(queue.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn pin_creation_accepts_only_identical_persisted_pin() {
    let url = path("secrets", &server_state_name("host", "server-uid"));

    for conflict in [false, true] {
        for changed in [false, true] {
            let mut proposed = host_pin();

            if changed {
                proposed.fingerprint = "changed-fingerprint".into();
            }

            let mut exchanges = vec![
                Exchange::missing("GET", &url),
                Exchange::reply(
                    "POST",
                    &path("secrets", ""),
                    if conflict { 409 } else { 201 },
                    if conflict {
                        status(409, "AlreadyExists")
                    } else {
                        json!(pin_object())
                    },
                ),
            ];

            if conflict {
                exchanges.push(Exchange::reply("GET", &url, 200, json!(pin_object())));
            }

            let (store, queue) = mock(exchanges);
            assert_eq!(
                store.save_pin("server-uid", &proposed).await.is_ok(),
                !changed
            );
            assert!(queue.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn pin_rejects_foreign_or_corrupt_state_and_endpoint_changes() {
    let url = path("secrets", &server_state_name("host", "server-uid"));

    for problem in ["foreign", "uid", "corrupt", "mutable", "address", "port"] {
        let mut secret = pin_object();
        let mut proposed = host_pin();
        match problem {
            "foreign" => secret.metadata.labels = None,
            "uid" => {
                secret
                    .metadata
                    .labels
                    .as_mut()
                    .unwrap()
                    .insert(SERVER_UID_LABEL.into(), "other-server".into());
            }

            "corrupt" => secret.data = None,
            "mutable" => secret.immutable = Some(false),
            "address" => proposed.address = "203.0.113.11".into(),
            _ => proposed.ssh_port = 2222,
        }

        let (store, queue) = mock(vec![Exchange::reply("GET", &url, 200, json!(secret))]);
        assert!(store.save_pin("server-uid", &proposed).await.is_err());
        assert!(queue.lock().unwrap().is_empty());
    }
}
