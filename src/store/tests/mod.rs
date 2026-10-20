use std::{
    collections::VecDeque,
    convert::Infallible,
    sync::{Arc, Mutex},
};

use http::{Request, Response};
use kube::client::Body;
use serde_json::{Value, json};
use tower::service_fn;

use super::*;
use crate::{
    allocation::Ledger,
    api::{
        BackendPort, PortRange, Protocol, ProxyProtocol, PublishedPort, SecretReference, Server,
        ServerSpec, ServiceRequest, SshSpec,
    },
};
use k8s_openapi::{ByteString, api::core::v1::Secret};
use std::collections::BTreeSet;

const ID: &str = "p-11111111111111111111111111111111";
const OTHER_ID: &str = "p-22222222222222222222222222222222";
const THIRD_ID: &str = "p-33333333333333333333333333333333";
const NAMESPACE: &str = "operator";

struct Exchange {
    method: &'static str,
    path: String,
    status: u16,
    respond: Box<dyn FnOnce(Value) -> Value + Send>,
}

impl Exchange {
    fn missing(method: &'static str, path: &str) -> Self {
        Self::reply(method, path, 404, status(404, "NotFound"))
    }

    fn reply(method: &'static str, path: &str, status: u16, response: Value) -> Self {
        Self::inspect(method, path, status, move |_| response)
    }

    fn inspect(
        method: &'static str,
        path: &str,
        status: u16,
        respond: impl FnOnce(Value) -> Value + Send + 'static,
    ) -> Self {
        Self {
            method,
            path: path.into(),
            status,
            respond: Box::new(respond),
        }
    }
}

fn mock(exchanges: Vec<Exchange>) -> (Store, Arc<Mutex<VecDeque<Exchange>>>) {
    let queue = Arc::new(Mutex::new(VecDeque::from(exchanges)));
    let service_queue = queue.clone();
    let service = service_fn(move |request: Request<Body>| {
        let exchange = service_queue
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected Kubernetes request");
        async move {
            assert_eq!(request.method().as_str(), exchange.method);
            assert_eq!(request.uri().path(), exchange.path);
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
    (
        Store::new(Client::new(service, "wrong-default"), NAMESPACE.into()),
        queue,
    )
}

fn path(resource: &str, name: &str) -> String {
    let collection = format!("/api/v1/namespaces/{NAMESPACE}/{resource}");

    if name.is_empty() {
        collection
    } else {
        format!("{collection}/{name}")
    }
}

fn status(code: u16, reason: &str) -> Value {
    json!({
        "apiVersion": "v1", "kind": "Status", "status": "Failure",
        "code": code, "reason": reason, "message": reason,
    })
}

fn record() -> PublicationRecord {
    PublicationRecord {
        publication: Publication {
            id: ID.into(),
            server_name: "edge".into(),
            server_uid: "server-uid".into(),
            server_address: "203.0.113.10".parse().unwrap(),
            control_port: 20000,
            service: ServiceRequest {
                namespace: "application".into(),
                name: "web".into(),
                uid: "service-uid".into(),
                cluster_ip: "10.96.1.10".parse().unwrap(),
                selector: BTreeMap::from([("app".into(), "web".into())]),
                ports: vec![PublishedPort {
                    name: "https".into(),
                    port: 443,
                    protocol: Protocol::Tcp,
                    proxy_protocol: ProxyProtocol::None,
                }],
                servers: vec!["edge".into()],
                pool: None,
                replicas: 1,
            },
        },
        server_spec: ServerSpec {
            address: "203.0.113.10".into(),
            ssh: SshSpec {
                user: "root".into(),
                port: 22,
                private_key_secret_ref: SecretReference {
                    name: "administrator-provided-key".into(),
                    key: "ssh-privatekey".into(),
                },
            },
            pool: None,
            allowed_namespaces: vec![],
            reserved_ports: vec![],
            control_port_range: PortRange::default(),
        },
        backend_ports: vec![BackendPort {
            protocol: Protocol::Tcp,
            port: 8443,
        }],
        config_hash: "desired-hash".into(),
        applied_hash: None,
        published: false,
        reserved: false,
        removing: false,
        credential_generation: None,
    }
}

fn server() -> Server {
    let record = record();
    let mut server = Server::new(&record.publication.server_name, record.server_spec);
    server.metadata.uid = Some(record.publication.server_uid);
    server
}

fn persisted_metadata(name: &str, kind: &str, version: &str) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.into()),
        namespace: Some(NAMESPACE.into()),
        labels: Some(server_labels(kind, "server-uid").unwrap()),
        uid: Some("kubernetes-object-uid".into()),
        resource_version: Some(version.into()),
        ..Default::default()
    }
}

fn record_object(record: &PublicationRecord, version: &str) -> ConfigMap {
    let mut metadata = persisted_metadata(&record.publication.id, "publication", version);
    metadata.labels = Some(publication_labels("publication", &record.publication).unwrap());
    ConfigMap {
        metadata,
        data: Some(BTreeMap::from([(
            "record.json".into(),
            serde_json::to_string(record).unwrap(),
        )])),
        ..Default::default()
    }
}

fn ledger_object(ledger: &Ledger, version: &str) -> ConfigMap {
    ConfigMap {
        metadata: persisted_metadata(
            &server_state_name("ports", "server-uid"),
            "allocation",
            version,
        ),
        data: Some(BTreeMap::from([(
            "ledger.json".into(),
            serde_json::to_string(ledger).unwrap(),
        )])),
        ..Default::default()
    }
}

fn credential_object() -> Secret {
    let mut metadata = persisted_metadata(&format!("credentials-{ID}"), "credentials", "7");
    metadata.labels = Some(publication_labels("credentials", &record().publication).unwrap());
    Secret {
        metadata,
        immutable: Some(true),
        type_: Some("Opaque".into()),
        data: Some(BTreeMap::from([
            ("token".into(), ByteString(b"persisted-token".to_vec())),
            (
                "tls.crt".into(),
                ByteString(b"persisted-certificate".to_vec()),
            ),
            (
                "tls.key".into(),
                ByteString(b"persisted-private-key".to_vec()),
            ),
        ])),
        ..Default::default()
    }
}

fn host_pin() -> HostPin {
    HostPin {
        known_hosts: "203.0.113.10 ssh-ed25519 public-key".into(),
        fingerprint: "SHA256:public-fingerprint".into(),
        address: "203.0.113.10".into(),
        ssh_port: 22,
    }
}

fn pin_object() -> Secret {
    Secret {
        metadata: persisted_metadata(&server_state_name("host", "server-uid"), "host-pin", "7"),
        immutable: Some(true),
        type_: Some("Opaque".into()),
        data: Some(BTreeMap::from([(
            "pin.json".into(),
            ByteString(serde_json::to_vec(&host_pin()).unwrap()),
        )])),
        ..Default::default()
    }
}

mod cleanup;
mod control;
mod identities;
mod leases;
mod records;
mod recovery;
