use std::net::Ipv4Addr;

use base64::{Engine, engine::general_purpose::STANDARD};

use super::{Operation, Request, ReservationRequest, pin::host_label};
use crate::{
    api::{Protocol, ProxyProtocol, Publication, PublishedPort, ServiceRequest},
    transport,
};

pub(super) fn host_key(address: Ipv4Addr, port: u16, seed: u8) -> String {
    let mut blob = Vec::new();

    for field in [b"ssh-ed25519".as_slice(), &[seed; 32]] {
        blob.extend_from_slice(&(field.len() as u32).to_be_bytes());
        blob.extend_from_slice(field);
    }

    format!(
        "{} ssh-ed25519 {}\n",
        host_label(address, port),
        STANDARD.encode(blob)
    )
}

pub(super) fn request(operation: Operation) -> Request {
    let address = "203.0.113.7".parse().unwrap();
    let publication = Publication {
        id: "pub-0123".into(),
        machine_name: "edge".into(),
        machine_uid: "machine-uid".into(),
        machine_address: address,
        control_port: 22000,
        service: ServiceRequest {
            namespace: "app".into(),
            name: "test".into(),
            uid: "service-uid".into(),
            cluster_ip: "10.96.1.2".parse().unwrap(),
            selector: Default::default(),
            ports: vec![
                PublishedPort {
                    name: "web".into(),
                    port: 443,
                    protocol: Protocol::Tcp,
                    proxy_protocol: ProxyProtocol::V2,
                },
                PublishedPort {
                    name: "dns".into(),
                    port: 53,
                    protocol: Protocol::Udp,
                    proxy_protocol: ProxyProtocol::None,
                },
            ],
            machines: vec!["edge".into()],
            pool: None,
            replicas: 1,
        },
    };

    let credentials = transport::credentials(&publication).unwrap();

    Request {
        operation,
        address,
        ssh_user: "debian".into(),
        ssh_port: 22,
        machine_uid: publication.machine_uid.clone(),
        server_config: Some(transport::server_config(&publication, &credentials).unwrap()),
        generation: Some(transport::credential_generation(
            &credentials.certificate_pem,
        )),
        server_certificate: Some(credentials.certificate_pem),
        server_private_key: Some(credentials.private_key_pem),
        publication: Some(publication),
        expected_known_hosts: Some(host_key(address, 22, 1)),
        reservation: Some(ReservationRequest {
            control_port_range: crate::api::PortRange::default(),
            excluded_ports: Vec::new(),
        }),
    }
}
