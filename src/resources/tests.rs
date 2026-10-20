use std::net::Ipv4Addr;

use super::*;
use crate::api::{BackendPort, Protocol, ProxyProtocol, PublishedPort, ServiceRequest};
use serde_json::{Value, json};

fn options() -> ResourceOptions {
    ResourceOptions {
        namespace: "tunnellb-system".into(),
        image: "example.test/tunnellb:v1.0.0".into(),
        pull_policy: "IfNotPresent".into(),
        service_account: "tunnellb-workload".into(),
    }
}

fn publication() -> Publication {
    Publication {
        id: "publication-123".into(),
        machine_name: "edge-one".into(),
        machine_uid: "machine-uid".into(),
        machine_address: Ipv4Addr::new(203, 0, 113, 7),
        control_port: 21001,
        service: ServiceRequest {
            namespace: "application".into(),
            name: "web".into(),
            uid: "service-uid".into(),
            cluster_ip: Ipv4Addr::new(10, 43, 0, 8),
            selector: BTreeMap::from([
                ("app".into(), "web".into()),
                ("tier".into(), "frontend".into()),
            ]),
            ports: vec![PublishedPort {
                name: "https".into(),
                port: 443,
                protocol: Protocol::Tcp,
                proxy_protocol: ProxyProtocol::None,
            }],
            machines: vec!["edge-one".into()],
            pool: None,
            replicas: 1,
        },
    }
}

fn backends() -> Vec<BackendPort> {
    [
        (Protocol::Udp, 8443),
        (Protocol::Tcp, 8443),
        (Protocol::Tcp, 8080),
        (Protocol::Tcp, 8443),
    ]
    .into_iter()
    .map(|(protocol, port)| BackendPort { protocol, port })
    .collect()
}

fn deployment() -> Value {
    serde_json::to_value(connector_deployment(
        &publication(),
        &backends(),
        "publication-config",
        &options(),
        "hash-one",
    ))
    .unwrap()
}

fn job() -> Value {
    serde_json::to_value(ssh_job(
        "enroll-123",
        Ipv4Addr::new(203, 0, 113, 8),
        2222,
        "enroll-request",
        "machine-key",
        "custom-ed25519",
        &options(),
    ))
    .unwrap()
}

fn connector_network_policy() -> Value {
    serde_json::to_value(connector_policy(&publication(), &backends(), &options())).unwrap()
}

fn ssh_network_policy() -> Value {
    serde_json::to_value(ssh_policy(
        "enroll-123",
        Ipv4Addr::new(203, 0, 113, 8),
        2222,
        &options(),
    ))
    .unwrap()
}

#[test]
fn resources_are_in_operator_namespace_without_owner_references() {
    for resource in [
        deployment(),
        job(),
        connector_network_policy(),
        ssh_network_policy(),
    ] {
        assert_eq!(resource["metadata"]["namespace"], "tunnellb-system");
        assert!(resource["metadata"].get("ownerReferences").is_none());

        if let Some(template) = resource["spec"].get("template") {
            assert!(template["metadata"].get("ownerReferences").is_none());
        }
    }
}

#[test]
fn connector_labels_bind_policy_and_deployment_to_the_exact_publication() {
    let deployment = deployment();
    let policy = connector_network_policy();
    let expected = json!({
        "app.kubernetes.io/managed-by": "tunnellb",
        "tunnellb.io/publication": "publication-123",
        "tunnellb.io/machine": "edge-one",
        "tunnellb.io/service-uid": "service-uid",
        "tunnellb.io/service-namespace": "application",
        "tunnellb.io/service-name": "web"
    });

    assert_eq!(deployment["metadata"]["name"], policy["metadata"]["name"]);

    for labels in [
        &deployment["metadata"]["labels"],
        &deployment["spec"]["template"]["metadata"]["labels"],
        &deployment["spec"]["selector"]["matchLabels"],
        &policy["spec"]["podSelector"]["matchLabels"],
        &policy["metadata"]["labels"],
    ] {
        assert_eq!(*labels, expected);
    }
}

#[test]
fn config_change_replaces_the_single_connector_without_changing_selector() {
    let original = deployment();
    assert_eq!(original["spec"]["replicas"], 1);
    assert_eq!(original["spec"]["strategy"], json!({"type": "Recreate"}));

    for (secret, hash) in [
        ("publication-config", "hash-two"),
        ("publication-config-v2", "hash-one"),
    ] {
        let changed = serde_json::to_value(connector_deployment(
            &publication(),
            &backends(),
            secret,
            &options(),
            hash,
        ))
        .unwrap();
        assert_eq!(original["spec"]["selector"], changed["spec"]["selector"]);
        assert_eq!(
            changed["spec"]["template"]["metadata"]["annotations"]["tunnellb.io/config-hash"],
            hash
        );
        assert_ne!(original["spec"]["template"], changed["spec"]["template"]);
    }
}

#[test]
fn both_workloads_harden_app_and_limit_root_to_the_guard() {
    for resource in [deployment(), job()] {
        let pod = &resource["spec"]["template"]["spec"];
        assert_eq!(pod["serviceAccountName"], options().service_account);

        for field in [
            "automountServiceAccountToken",
            "enableServiceLinks",
            "hostNetwork",
            "hostPID",
            "hostIPC",
            "shareProcessNamespace",
        ] {
            assert_eq!(pod[field], false);
        }

        let security = &pod["securityContext"];

        for field in ["fsGroup", "runAsUser", "runAsGroup"] {
            assert_eq!(security[field], 10001);
        }

        assert_eq!(security["runAsNonRoot"], true);
        assert_eq!(security["seccompProfile"]["type"], "RuntimeDefault");

        let containers = pod["containers"].as_array().unwrap();
        let init = pod["initContainers"].as_array().unwrap();
        assert_eq!(containers.len(), 1);
        assert_eq!(init.len(), 1);

        for container in containers.iter().chain(init) {
            let security = &container["securityContext"];
            assert_eq!(security["privileged"], false);
            assert_eq!(security["allowPrivilegeEscalation"], false);
            assert_eq!(security["readOnlyRootFilesystem"], true);
            assert_eq!(security["capabilities"]["drop"], json!(["ALL"]));
            assert_eq!(security["seccompProfile"]["type"], "RuntimeDefault");
        }

        let app = &containers[0]["securityContext"];
        assert_eq!(app["runAsUser"], 10001);
        assert_eq!(app["runAsGroup"], 10001);
        assert_eq!(app["runAsNonRoot"], true);
        assert!(app["capabilities"].get("add").is_none());
        assert_eq!(init[0]["securityContext"]["runAsUser"], 0);
        assert_eq!(init[0]["securityContext"]["runAsNonRoot"], false);
        assert_eq!(
            init[0]["securityContext"]["capabilities"]["add"],
            json!(["NET_ADMIN"])
        );

        let env = init[0]["env"].as_array().unwrap();
        let uid = env
            .iter()
            .find(|var| var["name"] == "TUNNELLB_POD_UID")
            .unwrap();
        assert_eq!(
            uid["valueFrom"]["fieldRef"],
            json!({
                "apiVersion": "v1", "fieldPath": "metadata.uid"
            })
        );
        assert!(uid.get("value").is_none());
        assert!(env.iter().any(
            |var| var["name"] == "XTABLES_LOCKFILE" && var["value"] == "/tmp/xtables.lock"
        ));
    }
}

#[test]
fn tmp_is_shared_and_secret_mounts_are_read_only_and_scoped() {
    for resource in [deployment(), job()] {
        let pod = &resource["spec"]["template"]["spec"];
        let volumes = pod["volumes"].as_array().unwrap();
        let tmp = volumes
            .iter()
            .find(|volume| volume["name"] == "tmp")
            .unwrap();
        assert_eq!(tmp["emptyDir"]["sizeLimit"], "64Mi");

        for container in pod["containers"]
            .as_array()
            .unwrap()
            .iter()
            .chain(pod["initContainers"].as_array().unwrap())
        {
            let mounts = container["volumeMounts"].as_array().unwrap();
            assert!(mounts.iter().any(|mount| mount["name"] == "tmp"
                && mount["mountPath"] == "/tmp"
                && mount["readOnly"] == false));
            for mount in mounts.iter().filter(|mount| mount["name"] != "tmp") {
                assert_eq!(mount["readOnly"], true);
            }
        }

        for volume in volumes {
            assert!(volume.get("hostPath").is_none());
            assert!(volume.get("projected").is_none());

            if let Some(secret) = volume.get("secret") {
                assert_eq!(secret["defaultMode"], 0o440);
                assert_eq!(secret["optional"], false);
                for item in secret["items"].as_array().unwrap() {
                    assert_eq!(item["mode"], 0o440);
                }
            }
        }
    }
}

#[test]
fn connector_uses_exact_config_keys_and_independent_heartbeat_probes() {
    let deployment = deployment();
    let pod = &deployment["spec"]["template"]["spec"];
    assert_eq!(pod["volumes"].as_array().unwrap().len(), 2);
    assert_eq!(
        pod["volumes"][0]["secret"]["secretName"],
        "publication-config"
    );
    assert_eq!(
        pod["volumes"][0]["secret"]["items"],
        json!([
            {"key": "frpc.toml", "path": "frpc.toml", "mode": 0o440},
            {"key": "ca.crt", "path": "ca.crt", "mode": 0o440},
            {"key": "guard.json", "path": "guard.json", "mode": 0o440}
        ])
    );

    let app = &pod["containers"][0];

    for (name, path) in [
        ("readinessProbe", "/tmp/tunnellb-ready"),
        ("livenessProbe", "/tmp/tunnellb-alive"),
    ] {
        let probe = &app[name];
        assert_eq!(
            probe["exec"]["command"],
            json!(["/usr/local/bin/tunnellb", "ready", "--path", path])
        );
        assert!(probe.get("httpGet").is_none());
        assert!(probe.get("tcpSocket").is_none());
    }

    let liveness = &app["livenessProbe"];
    assert!(
        liveness["periodSeconds"].as_i64().unwrap()
            * liveness["failureThreshold"].as_i64().unwrap()
            >= 60
    );
}

#[test]
fn connector_policy_allows_only_edge_and_combined_namespace_backend_peers() {
    let policy = connector_network_policy();
    let spec = &policy["spec"];
    assert_eq!(spec["policyTypes"], json!(["Ingress", "Egress"]));
    assert_eq!(spec["ingress"], json!([]));
    let rules = spec["egress"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(
        rules[0],
        json!({
            "to": [{"ipBlock": {"cidr": "203.0.113.7/32"}}],
            "ports": [{"protocol": "TCP", "port": 21001}]
        })
    );
    assert_eq!(
        rules[1],
        json!({
            "to": [{
                "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "application"}},
                "podSelector": {"matchLabels": {"app": "web", "tier": "frontend"}}
            }],
            "ports": [
                {"protocol": "TCP", "port": 8080},
                {"protocol": "TCP", "port": 8443},
                {"protocol": "UDP", "port": 8443}
            ]
        })
    );

    let mut ports = backends();
    ports.reverse();
    ports.push(ports[0].clone());
    assert_eq!(
        policy,
        serde_json::to_value(connector_policy(&publication(), &ports, &options())).unwrap()
    );
}

#[test]
fn empty_backend_selector_or_ports_cannot_open_namespace_or_all_ports() {
    for (empty_selector, empty_ports) in [(false, true), (true, false), (true, true)] {
        let mut publication = publication();

        if empty_selector {
            publication.service.selector.clear();
        }

        let ports = if empty_ports { vec![] } else { backends() };
        let policy = connector_policy(&publication, &ports, &options());
        assert_eq!(
            serde_json::to_value(policy).unwrap()["spec"]["egress"],
            json!([{
                "to": [{"ipBlock": {"cidr": "203.0.113.7/32"}}],
                "ports": [{"protocol": "TCP", "port": 21001}]
            }])
        );
    }
}

#[test]
fn ssh_job_bounds_execution_and_scopes_worker_secrets() {
    let job = job();
    let spec = &job["spec"];
    assert!(
        spec["activeDeadlineSeconds"].as_u64().unwrap()
            > crate::provision::OPERATION_TIMEOUT.as_secs(),
        "Kubernetes must allow the worker's bounded operation to finish"
    );
    assert_eq!(spec["backoffLimit"], 1);

    let pod = &spec["template"]["spec"];
    assert_eq!(pod["restartPolicy"], "Never");
    assert_eq!(pod["volumes"].as_array().unwrap().len(), 3);
    assert_eq!(
        pod["volumes"][0]["secret"],
        json!({
            "secretName": "enroll-request", "defaultMode": 0o440, "optional": false,
            "items": [{"key": "request.json", "path": "request.json", "mode": 0o440}]
        })
    );
    assert_eq!(
        pod["volumes"][1]["secret"],
        json!({
            "secretName": "machine-key", "defaultMode": 0o440, "optional": false,
            "items": [{"key": "custom-ed25519", "path": "ssh-privatekey", "mode": 0o440}]
        })
    );

    let worker = &pod["containers"][0];

    assert_eq!(
        worker["volumeMounts"],
        json!([
            {"name": "request", "mountPath": "/etc/request", "readOnly": true},
            {"name": "ssh-key", "mountPath": "/etc/ssh-key", "readOnly": true},
            {"name": "tmp", "mountPath": "/tmp", "readOnly": false}
        ])
    );

    for container in [worker, &pod["initContainers"][0]] {
        assert!(container.get("readinessProbe").is_none());
        assert!(container.get("livenessProbe").is_none());
        assert!(container.get("startupProbe").is_none());
    }

    let guard = &pod["initContainers"][0];
    assert_eq!(
        guard["args"],
        json!(["guard", "--allow", "203.0.113.8:2222"])
    );
    assert_eq!(
        guard["volumeMounts"],
        json!([
            {"name": "tmp", "mountPath": "/tmp", "readOnly": false}
        ])
    );
}

#[test]
fn ssh_policy_selects_only_its_operation_and_allows_only_ssh() {
    let policy = ssh_network_policy();
    let job = job();
    let labels = &job["spec"]["template"]["metadata"]["labels"];
    assert_eq!(labels[SSH_JOB_LABEL], "enroll-123");
    assert_eq!(policy["spec"]["podSelector"]["matchLabels"], *labels);
    assert_eq!(policy["metadata"]["name"], job["metadata"]["name"]);
    assert_eq!(policy["spec"]["policyTypes"], json!(["Ingress", "Egress"]));
    assert_eq!(policy["spec"]["ingress"], json!([]));
    assert_eq!(
        policy["spec"]["egress"],
        json!([{
            "to": [{"ipBlock": {"cidr": "203.0.113.8/32"}}],
            "ports": [{"protocol": "TCP", "port": 2222}]
        }])
    );
    let other = serde_json::to_value(ssh_policy(
        "enroll-456",
        Ipv4Addr::new(203, 0, 113, 8),
        2222,
        &options(),
    ))
    .unwrap();
    assert_ne!(policy["spec"]["podSelector"], other["spec"]["podSelector"]);
}
