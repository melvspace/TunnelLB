use super::*;
use crate::api::{MachineSpec, PortRange, ProxyProtocol, PublishedPort, SecretReference, SshSpec};

fn machine() -> Machine {
    let mut machine = Machine::new(
        "edge",
        MachineSpec {
            address: "203.0.113.10".into(),
            ssh: SshSpec {
                user: "root".into(),
                port: 22,
                private_key_secret_ref: SecretReference {
                    name: "ssh".into(),
                    key: "ssh-privatekey".into(),
                },
            },
            pool: None,
            allowed_namespaces: Vec::new(),
            reserved_ports: Vec::new(),
            control_port_range: PortRange {
                start: 20000,
                end: 20003,
            },
        },
    );
    machine.metadata.uid = Some("machine-uid".into());
    machine
}

fn service(uid: &str, ports: &[(Protocol, u16)]) -> ServiceRequest {
    ServiceRequest {
        namespace: "apps".into(),
        name: format!("service-{uid}"),
        uid: uid.into(),
        cluster_ip: "10.96.0.10".parse().unwrap(),
        selector: BTreeMap::from([("app".into(), "demo".into())]),
        ports: ports
            .iter()
            .enumerate()
            .map(|(index, &(protocol, port))| PublishedPort {
                name: format!("port-{index}"),
                port,
                protocol,
                proxy_protocol: ProxyProtocol::None,
            })
            .collect(),
        machines: vec!["edge".into()],
        pool: None,
        replicas: 1,
    }
}

fn assert_rejected(
    ledger: &mut Ledger,
    id: &str,
    service: &ServiceRequest,
    machine: &Machine,
) -> anyhow::Error {
    let before = ledger.clone();
    let error = ledger.allocate(id, service, machine).unwrap_err();
    assert_eq!(
        *ledger, before,
        "failed allocation must leave the ledger unchanged"
    );
    error
}

mod ownership;
mod recovery;
mod reservations;
