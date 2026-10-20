use std::collections::BTreeMap;

use k8s_openapi::{
    api::core::v1::{
        Capabilities, Container, EmptyDirVolumeSource, EnvVar, EnvVarSource, ExecAction, KeyToPath,
        ObjectFieldSelector, PodSecurityContext, PodSpec, Probe, ResourceRequirements,
        SeccompProfile, SecretVolumeSource, SecurityContext, Volume, VolumeMount,
    },
    apimachinery::pkg::api::resource::Quantity,
};

use super::ResourceOptions;

const BINARY: &str = "/usr/local/bin/tunnellb";
const WORKLOAD_UID: i64 = 10001;

pub(super) fn container(
    name: &str,
    args: &[&str],
    mounts: Vec<VolumeMount>,
    options: &ResourceOptions,
) -> Container {
    Container {
        name: name.into(),
        image: Some(options.image.clone()),
        image_pull_policy: Some(options.pull_policy.clone()),
        command: Some(vec![BINARY.into()]),
        args: Some(args.iter().map(|arg| (*arg).into()).collect()),
        security_context: Some(SecurityContext {
            run_as_non_root: Some(true),
            run_as_user: Some(WORKLOAD_UID),
            run_as_group: Some(WORKLOAD_UID),
            allow_privilege_escalation: Some(false),
            privileged: Some(false),
            read_only_root_filesystem: Some(true),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".into()]),
                ..Default::default()
            }),
            seccomp_profile: Some(runtime_default()),
            ..Default::default()
        }),
        resources: Some(resources("100m", "64Mi", "500m", "256Mi")),
        volume_mounts: Some(mounts),
        ..Default::default()
    }
}

pub(super) fn guard_container(
    args: &[&str],
    mounts: Vec<VolumeMount>,
    options: &ResourceOptions,
) -> Container {
    let mut guard = container("egress-guard", args, mounts, options);
    let security = guard.security_context.as_mut().expect("container security");

    // Only this short-lived init process can install rules in the pod netns.
    security.run_as_non_root = Some(false);
    security.run_as_user = Some(0);
    security.run_as_group = Some(0);
    security
        .capabilities
        .as_mut()
        .expect("container capabilities")
        .add = Some(vec!["NET_ADMIN".into()]);

    guard.env = Some(vec![
        EnvVar {
            name: "TUNNELLB_POD_UID".into(),
            value_from: Some(EnvVarSource {
                field_ref: Some(ObjectFieldSelector {
                    api_version: Some("v1".into()),
                    field_path: "metadata.uid".into(),
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
        // Keep the xtables lock writable with a read-only root filesystem.
        EnvVar {
            name: "XTABLES_LOCKFILE".into(),
            value: Some("/tmp/xtables.lock".into()),
            ..Default::default()
        },
    ]);
    guard.resources = Some(resources("10m", "16Mi", "100m", "64Mi"));

    guard
}

pub(super) fn pod_spec(
    workload: Container,
    guard: Container,
    volumes: Vec<Volume>,
    restart_policy: &str,
    options: &ResourceOptions,
) -> PodSpec {
    PodSpec {
        containers: vec![workload],
        init_containers: Some(vec![guard]),
        volumes: Some(volumes),
        restart_policy: Some(restart_policy.into()),
        service_account_name: Some(options.service_account.clone()),
        automount_service_account_token: Some(false),
        enable_service_links: Some(false),
        host_network: Some(false),
        host_pid: Some(false),
        host_ipc: Some(false),
        share_process_namespace: Some(false),
        security_context: Some(PodSecurityContext {
            run_as_non_root: Some(true),
            run_as_user: Some(WORKLOAD_UID),
            run_as_group: Some(WORKLOAD_UID),
            fs_group: Some(WORKLOAD_UID),
            seccomp_profile: Some(runtime_default()),
            ..Default::default()
        }),
        termination_grace_period_seconds: Some(10),
        ..Default::default()
    }
}

fn runtime_default() -> SeccompProfile {
    SeccompProfile {
        type_: "RuntimeDefault".into(),
        ..Default::default()
    }
}

fn resources(cpu: &str, memory: &str, cpu_limit: &str, memory_limit: &str) -> ResourceRequirements {
    ResourceRequirements {
        requests: Some(BTreeMap::from([
            ("cpu".into(), Quantity(cpu.into())),
            ("memory".into(), Quantity(memory.into())),
        ])),
        limits: Some(BTreeMap::from([
            ("cpu".into(), Quantity(cpu_limit.into())),
            ("memory".into(), Quantity(memory_limit.into())),
        ])),
        ..Default::default()
    }
}

pub(super) fn secret_volume(name: &str, secret: &str, items: &[(&str, &str)]) -> Volume {
    Volume {
        name: name.into(),
        secret: Some(SecretVolumeSource {
            secret_name: Some(secret.into()),
            default_mode: Some(0o440),
            optional: Some(false),
            items: Some(
                items
                    .iter()
                    .map(|(key, path)| KeyToPath {
                        key: (*key).into(),
                        path: (*path).into(),
                        mode: Some(0o440),
                    })
                    .collect(),
            ),
        }),
        ..Default::default()
    }
}

pub(super) fn volume_mount(name: &str, path: &str, read_only: bool) -> VolumeMount {
    VolumeMount {
        name: name.into(),
        mount_path: path.into(),
        read_only: Some(read_only),
        ..Default::default()
    }
}

pub(super) fn tmp_mount() -> VolumeMount {
    volume_mount("tmp", "/tmp", false)
}

pub(super) fn tmp_volume() -> Volume {
    Volume {
        name: "tmp".into(),
        empty_dir: Some(EmptyDirVolumeSource {
            size_limit: Some(Quantity("64Mi".into())),
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub(super) fn marker_probe(path: &str, initial_delay: i32, period: i32, failures: i32) -> Probe {
    Probe {
        exec: Some(ExecAction {
            command: Some(vec![
                BINARY.into(),
                "ready".into(),
                "--path".into(),
                path.into(),
            ]),
        }),
        initial_delay_seconds: Some(initial_delay),
        period_seconds: Some(period),
        failure_threshold: Some(failures),
        timeout_seconds: Some(2),
        ..Default::default()
    }
}
