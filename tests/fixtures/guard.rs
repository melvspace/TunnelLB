use crate::{
    cluster::{execute, text},
    setup::Run,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::process::Output;

impl Run {
    pub(super) fn guard(&self) -> Result<()> {
        eprintln!(
            "e2e: guard-only pod; exact allowlist and denied API/node/unpublished destinations"
        );
        let deployment = self.connector("echo")?;
        let config_name = deployment["spec"]["template"]["spec"]["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|v| v["secret"]["secretName"].as_str())
            .context("connector Secret missing")?;
        let secret = self.get(&self.operator, "secret", config_name)?;
        self.env.apply(&json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": config_name, "namespace": self.app},
            "immutable": true,
            "type": "Opaque",
            "data": secret["data"]
        }))?;

        let mut spec = deployment["spec"]["template"]["spec"].clone();
        spec["serviceAccountName"] = json!("default");
        spec["containers"][0]["name"] = json!("probe");
        spec["containers"][0]["command"] = json!(["/bin/bash", "-c", "exec sleep 900"]);
        spec["containers"][0]["args"] = json!([]);
        spec["containers"][0]
            .as_object_mut()
            .unwrap()
            .remove("readinessProbe");
        spec["containers"][0]
            .as_object_mut()
            .unwrap()
            .remove("livenessProbe");
        self.env.apply(&json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "guard-probe",
                "namespace": self.app,
                "labels": {"app": "guard-probe"}
            },
            "spec": spec
        }))?;
        self.env.kubectl(&[
            "-n",
            &self.app,
            "wait",
            "pod/guard-probe",
            "--for=condition=Ready",
            "--timeout=90s",
        ])?;

        // No NetworkPolicy exists in this namespace: rejection below is evidence
        // of the actual init-installed pod-local guard, not the outer CNI policy.
        ensure!(
            self.list(&self.app, "networkpolicies", "")?.is_empty(),
            "guard probe must not be masked by a NetworkPolicy"
        );
        let identity = text(self.env.kubectl(&[
            "-n",
            &self.app,
            "exec",
            "guard-probe",
            "--",
            "bash",
            "-c",
            r#"set -e
id -u
grep -E '^(CapEff|NoNewPrivs):' /proc/self/status
stat -c '%u %a' /tmp/tunnellb-guard-installed
test "$(cat /tmp/tunnellb-guard-installed)" = "$(readlink /proc/self/ns/net)"
"#,
        ])?)?;
        ensure!(
            identity.contains("10001")
                && identity.contains("CapEff:\t0000000000000000")
                && identity.contains("NoNewPrivs:\t1")
                && identity.contains("0 444"),
            "guard or workload security context mismatch"
        );

        let service = self.get(&self.app, "service", "echo")?;
        let cluster_ip = service["spec"]["clusterIP"].as_str().unwrap();
        let response = self.probe(&format!(
            "exec 3<>/dev/tcp/{cluster_ip}/18080; printf 'guard-allowed\\n' >&3; head -n1 <&3"
        ))?;
        ensure!(
            response.status.success(),
            "guard blocked the approved Service VIP"
        );
        let response: Value = serde_json::from_slice(&response.stdout)?;
        ensure!(response["payload"] == "guard-allowed");

        let api = self.get("default", "service", "kubernetes")?["spec"]["clusterIP"]
            .as_str()
            .unwrap()
            .to_owned();
        let nodes = self.env.json(&[
            "get",
            "nodes",
            "-l",
            "node-role.kubernetes.io/control-plane",
            "-o",
            "json",
        ])?;
        let node_ip = nodes["items"][0]["status"]["addresses"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["type"] == "InternalIP")
            .unwrap()["address"]
            .as_str()
            .unwrap()
            .to_owned();
        let backend = self.list(&self.app, "pods", "app=e2e-backend")?[0]["status"]["podIP"]
            .as_str()
            .unwrap()
            .to_owned();

        for (ip, port) in [
            (api, 443),
            (node_ip, 6443),
            (self.env.address.to_string(), 18090),
            (backend, 8083),
        ] {
            // Establish that the target accepts TCP without the guard first.
            self.env.kubectl(&[
                "-n", &self.app, "exec", "deployment/backend", "--",
                "python3", "-c",
                "import socket,sys; socket.create_connection((sys.argv[1],int(sys.argv[2])),3).close()",
                &ip, &port.to_string(),
            ])?;
            let denied = self.probe(&format!(
                "timeout 3 bash -c 'exec 3<>/dev/tcp/{ip}/{port}'; result=$?; \
                 test \"$result\" -eq 124 || exit 1; printf 'guard-connect-timed-out\\n'"
            ))?;
            ensure!(
                denied.status.success() && denied.stdout == b"guard-connect-timed-out\n",
                "guard did not time out a reachable forbidden destination {ip}:{port}"
            );
        }

        self.env.kubectl(&[
            "-n",
            &self.app,
            "delete",
            "pod",
            "guard-probe",
            "--wait=true",
            "--timeout=30s",
        ])?;
        self.env
            .kubectl(&["-n", &self.app, "delete", "secret", config_name])?;

        Ok(())
    }

    pub(super) fn probe(&self, script: &str) -> Result<Output> {
        execute(
            "kubectl",
            &[
                "--kubeconfig",
                &self.env.kubeconfig,
                "--context",
                &self.env.context,
                "--request-timeout=15s",
                "-n",
                &self.app,
                "exec",
                "guard-probe",
                "--",
                "timeout",
                "8",
                "bash",
                "-c",
                script,
            ],
            None,
            20,
        )
    }
}
