use std::{collections::BTreeMap, net::SocketAddrV4};

use k8s_openapi::{
    api::{
        apps::v1::{Deployment, DeploymentSpec, DeploymentStrategy},
        batch::v1::{Job, JobSpec},
        core::v1::PodTemplateSpec,
    },
    apimachinery::pkg::apis::meta::v1::ObjectMeta,
};

use crate::api::{BackendPort, Publication};

use super::{
    ResourceOptions, metadata,
    pod::{
        container, guard_container, marker_probe, pod_spec, secret_volume, tmp_mount, tmp_volume,
        volume_mount,
    },
    publication_labels, selector, ssh_labels,
};

const CONFIG_HASH_ANNOTATION: &str = "tunnellb.io/config-hash";
const HEALTH_ANNOTATION: &str = "tunnellb.io/health-checks";

/// The Deployment and its NetworkPolicy both use the publication ID as their name.
///
/// Guard destinations are supplied by the immutable Secret's `guard.json`;
/// `config_hash` must cover that configuration as well as the FRP configuration.
pub fn connector_deployment(
    publication: &Publication,
    _backend_ports: &[BackendPort],
    secret_name: &str,
    options: &ResourceOptions,
    config_hash: &str,
) -> Deployment {
    let labels = publication_labels(publication);
    let mounts = vec![volume_mount("config", "/etc/tunnellb", true), tmp_mount()];
    let mut connector = container(
        "connector",
        &["connector", "--config", "/etc/tunnellb/frpc.toml"],
        mounts.clone(),
        options,
    );
    connector.readiness_probe = Some(marker_probe("/tmp/tunnellb-ready", 2, 2, 3));
    // The wrapper refreshes its own heartbeat during reconnection. Remote
    // availability therefore changes readiness without causing restart loops.
    connector.liveness_probe = Some(marker_probe("/tmp/tunnellb-alive", 10, 10, 6));
    let guard = guard_container(
        &["guard", "--config", "/etc/tunnellb/guard.json"],
        mounts,
        options,
    );
    let pod = pod_spec(
        connector,
        guard,
        vec![
            secret_volume(
                "config",
                secret_name,
                &[
                    ("frpc.toml", "frpc.toml"),
                    ("ca.crt", "ca.crt"),
                    ("guard.json", "guard.json"),
                ],
            ),
            tmp_volume(),
        ],
        "Always",
        options,
    );

    Deployment {
        metadata: metadata(&publication.id, labels.clone(), options),
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: selector(labels.clone()),
            strategy: Some(DeploymentStrategy {
                type_: Some("Recreate".into()),
                ..Default::default()
            }),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    annotations: Some(BTreeMap::from([
                        (CONFIG_HASH_ANNOTATION.into(), config_hash.into()),
                        (
                            HEALTH_ANNOTATION.into(),
                            "Exec probes check separate readiness and process-heartbeat markers; \
                             FRP reconnects independently during edge outages."
                                .into(),
                        ),
                    ])),
                    ..Default::default()
                }),
                spec: Some(pod),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Create a finite SSH operation. `name` uniquely identifies both its Job and policy.
/// `control_port` is supplied only for Apply, after validating its publication.
pub fn ssh_job(
    name: &str,
    address: SocketAddrV4,
    control_port: Option<u16>,
    request_secret: &str,
    key_secret: &str,
    key_field: &str,
    options: &ResourceOptions,
) -> Job {
    let labels = ssh_labels(name);
    let mut worker = container(
        "ssh-worker",
        &[
            "ssh-worker",
            "--request",
            "/etc/request/request.json",
            "--key",
            "/etc/ssh-key/ssh-privatekey",
            "--result",
            "/dev/termination-log",
        ],
        vec![
            volume_mount("request", "/etc/request", true),
            volume_mount("ssh-key", "/etc/ssh-key", true),
            tmp_mount(),
        ],
        options,
    );
    worker.termination_message_path = Some("/dev/termination-log".into());
    worker.termination_message_policy = Some("File".into());
    let address = address.to_string();
    let control_port = control_port.map(|port| port.to_string());
    let mut guard_args = vec!["guard", "--allow", address.as_str()];

    if let Some(port) = control_port.as_deref() {
        guard_args.extend(["--control-port", port]);
    }

    let guard = guard_container(&guard_args, vec![tmp_mount()], options);

    Job {
        metadata: metadata(name, labels.clone(), options),
        spec: Some(JobSpec {
            active_deadline_seconds: Some(600),
            backoff_limit: Some(1),
            completions: Some(1),
            parallelism: Some(1),
            ttl_seconds_after_finished: Some(3600),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    annotations: Some(BTreeMap::from([(
                        HEALTH_ANNOTATION.into(),
                        "Finite SSH operation: exit status and termination result report success \
                         or failure; the Job deadline bounds execution, so probes are omitted."
                            .into(),
                    )])),
                    ..Default::default()
                }),
                spec: Some(pod_spec(
                    worker,
                    guard,
                    vec![
                        secret_volume(
                            "request",
                            request_secret,
                            &[("request.json", "request.json")],
                        ),
                        secret_volume("ssh-key", key_secret, &[(key_field, "ssh-privatekey")]),
                        tmp_volume(),
                    ],
                    "Never",
                    options,
                )),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}
