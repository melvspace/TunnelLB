use crate::{
    cluster::{text, wait_for},
    setup::Run,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use tunnellb::provision::Outcome;

impl Run {
    pub(super) fn enrollment(&self) -> Result<()> {
        eprintln!("e2e: real SSH enrollment and persisted host pin");
        wait_for("Machine enrollment", 180, || {
            Ok(self.get(&self.operator, "machine", &self.machine)?["status"]["phase"] == "Ready")
        })?;
        let jobs = self.list(
            &self.operator,
            "jobs",
            &format!("tunnellb.io/machine={}", self.machine),
        )?;
        let successful_jobs: Vec<_> = jobs
            .iter()
            .filter(|job| job["status"]["succeeded"].as_u64() == Some(1))
            .collect();
        ensure!(
            successful_jobs.len() >= 2,
            "enrollment must finish separate TOFU and pinned-install Jobs"
        );
        let pins = self.list(&self.operator, "secrets", "tunnellb.io/kind=host-pin")?;
        ensure!(
            pins.len() == 1 && pins[0]["immutable"] == true,
            "one immutable host pin required"
        );
        let pin: Value = serde_json::from_slice(
            &STANDARD.decode(
                pins[0]["data"]["pin.json"]
                    .as_str()
                    .context("missing pin")?,
            )?,
        )?;
        let known_hosts = pin["known_hosts"]
            .as_str()
            .filter(|hosts| !hosts.trim().is_empty())
            .context("host pin has no known_hosts")?;
        let pinned_fingerprint = pin["fingerprint"]
            .as_str()
            .context("host pin has no fingerprint")?;
        let fingerprint =
            text(
                self.env
                    .docker(&["ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub"])?,
            )?;
        ensure!(
            fingerprint.split_whitespace().nth(1) == Some(pinned_fingerprint),
            "recorded pin does not match the real edge host key"
        );

        let mut discoveries = 0;
        let mut installations = 0;

        for job in successful_jobs {
            let name = job["metadata"]["name"]
                .as_str()
                .context("enrollment Job has no name")?;
            let (request, outcome) = self
                .enrollment_result(job)
                .with_context(|| format!("checking enrollment Job {name}"))?;
            ensure!(
                request["operation"] == "enroll",
                "Job {name} did not execute enrollment"
            );
            ensure!(
                outcome.known_hosts == known_hosts && outcome.fingerprint == pinned_fingerprint,
                "Job {name} outcome does not match the persisted host pin"
            );
            let expected_hosts = request
                .get("expectedKnownHosts")
                .context("enrollment request has no expectedKnownHosts")?;

            if expected_hosts.is_null() {
                ensure!(
                    outcome.architecture.is_empty(),
                    "TOFU Job {name} must report discovery without installation"
                );
                discoveries += 1;
            } else {
                ensure!(
                    expected_hosts.as_str() == Some(known_hosts),
                    "installation Job {name} did not use the persisted host pin"
                );
                ensure!(
                    matches!(outcome.architecture.as_str(), "amd64" | "arm64"),
                    "pinned Job {name} did not report a completed installation"
                );
                installations += 1;
            }
        }

        ensure!(
            discoveries >= 1 && installations >= 1,
            "successful enrollment Jobs must contain discovery and pinned installation"
        );
        Ok(())
    }

    fn enrollment_result(&self, job: &Value) -> Result<(Value, Outcome)> {
        let name = job["metadata"]["name"]
            .as_str()
            .context("Job name missing")?;
        let uid = job["metadata"]["uid"].as_str().context("Job UID missing")?;
        ensure!(
            job["status"]["conditions"]
                .as_array()
                .is_some_and(|conditions| conditions
                    .iter()
                    .any(|condition| condition["type"] == "Complete"
                        && condition["status"] == "True")),
            "enrollment Job has not completed"
        );
        let secret_name = request_secret(&job["spec"]["template"]["spec"])?;
        let secret = self.get(&self.operator, "secret", secret_name)?;
        let request = serde_json::from_slice(
            &STANDARD.decode(
                secret["data"]["request.json"]
                    .as_str()
                    .context("mounted Secret has no request")?,
            )?,
        )?;
        let pods = self.list(
            &self.operator,
            "pods",
            &format!("batch.kubernetes.io/job-name={name}"),
        )?;
        let successful_pods: Vec<_> = pods
            .iter()
            .filter(|pod| {
                pod["status"]["phase"] == "Succeeded"
                    && pod["metadata"]["ownerReferences"]
                        .as_array()
                        .is_some_and(|owners| {
                            owners.iter().any(|owner| {
                                owner["apiVersion"] == "batch/v1"
                                    && owner["kind"] == "Job"
                                    && owner["name"] == name
                                    && owner["uid"] == uid
                                    && owner["controller"] == true
                            })
                        })
            })
            .collect();
        ensure!(
            successful_pods.len() == 1,
            "enrollment Job must own exactly one successful Pod"
        );
        let pod = successful_pods[0];
        ensure!(
            request_secret(&pod["spec"])? == secret_name,
            "successful Pod did not mount its Job's request Secret"
        );
        let worker = pod["status"]["containerStatuses"]
            .as_array()
            .context("successful Pod has no container statuses")?
            .iter()
            .find(|container| container["name"] == "ssh-worker")
            .context("successful Pod has no SSH worker status")?;
        let terminated = &worker["state"]["terminated"];
        ensure!(
            terminated["exitCode"] == 0,
            "SSH worker did not terminate successfully"
        );
        let outcome = serde_json::from_str(
            terminated["message"]
                .as_str()
                .context("SSH worker has no termination outcome")?,
        )?;
        Ok((request, outcome))
    }
}

fn request_secret(spec: &Value) -> Result<&str> {
    let worker = spec["containers"]
        .as_array()
        .context("Pod spec has no containers")?
        .iter()
        .find(|container| container["name"] == "ssh-worker")
        .context("Pod spec has no SSH worker")?;
    let mount = worker["volumeMounts"]
        .as_array()
        .context("SSH worker has no volume mounts")?
        .iter()
        .find(|mount| mount["mountPath"] == "/etc/request")
        .context("SSH worker has no request mount")?;
    let volume_name = mount["name"]
        .as_str()
        .context("request mount has no volume name")?;
    spec["volumes"]
        .as_array()
        .context("Pod spec has no volumes")?
        .iter()
        .find(|volume| volume["name"] == volume_name)
        .context("request volume missing")?["secret"]["secretName"]
        .as_str()
        .context("request volume does not reference a Secret")
}
