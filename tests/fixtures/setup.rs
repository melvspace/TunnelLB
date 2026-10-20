use crate::cluster::{BASE, Environment, checked, enabled};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{env, fs};
use tempfile::TempDir;

pub(super) const BACKEND_IMAGE: &str = "tunnellb-e2e-backend:0.1.0";

pub(super) struct Run {
    pub(super) env: Environment,
    pub(super) scratch: TempDir,
    pub(super) app: String,
    pub(super) operator: String,
    pub(super) server: String,
    image_tag: String,
    pub(super) installed: bool,
    resources_created: bool,
    pub(super) success: bool,
}

impl Run {
    pub(super) fn new(env: Environment) -> Result<Self> {
        fs::create_dir_all(BASE)?;
        let scratch = tempfile::Builder::new().prefix("run-").tempdir_in(BASE)?;
        let id = &uuid::Uuid::new_v4().simple().to_string()[..10];
        let name = format!("tunnellb-e2e-{id}");

        Ok(Self {
            env,
            scratch,
            app: format!("{name}-app"),
            operator: format!("{name}-system"),
            server: format!("{name}-edge"),
            image_tag: env::var("TUNNELLB_E2E_IMAGE_TAG").unwrap_or_else(|_| "0.1.0".into()),
            installed: false,
            resources_created: false,
            success: false,
        })
    }

    pub(super) fn get(&self, namespace: &str, kind: &str, name: &str) -> Result<Value> {
        self.env
            .json(&["-n", namespace, "get", kind, name, "-o", "json"])
    }

    pub(super) fn list(&self, namespace: &str, kind: &str, selector: &str) -> Result<Vec<Value>> {
        let value = self
            .env
            .json(&["-n", namespace, "get", kind, "-l", selector, "-o", "json"])?;

        Ok(value["items"]
            .as_array()
            .context("resource list missing")?
            .clone())
    }

    pub(super) fn setup(&mut self) -> Result<()> {
        eprintln!("e2e: setup; operator namespace {}", self.operator);
        let controllers = self.env.json(&[
            "get",
            "deployments",
            "-A",
            "-l",
            "app.kubernetes.io/name=tunnellb",
            "-o",
            "json",
        ])?;
        ensure!(
            controllers["items"].as_array().is_some_and(Vec::is_empty),
            "stop the prior test operator before running this isolated suite"
        );
        let services = self.env.json(&["get", "services", "-A", "-o", "json"])?;
        ensure!(
            services["items"]
                .as_array()
                .context("Service list missing")?
                .iter()
                .all(|service| service["spec"]["loadBalancerClass"] != "tunnellb.io/edge"),
            "remove prior TunnelLB Services before starting this suite's controller"
        );
        let crds = self.env.json(&["get", "crds", "-o", "json"])?;

        if crds["items"]
            .as_array()
            .context("CRD list missing")?
            .iter()
            .any(|crd| crd["metadata"]["name"] == "servers.tunnellb.io")
        {
            let servers = self.env.json(&["get", "servers", "-o", "json"])?;
            ensure!(
                servers["items"].as_array().is_some_and(Vec::is_empty),
                "remove prior test Servers before starting this suite's controller"
            );
        }

        self.env
            .docker(&["test", "!", "-e", "/var/lib/tunnellb/owner"])
            .context(
                "a fresh disposable edge is required; recreate it after a previous enrollment",
            )?;

        let image = format!("tunnellb:{}", self.image_tag);

        if !enabled("TUNNELLB_E2E_SKIP_BUILD") {
            checked("docker", &["build", "-t", &image, "."], None, 1200)?;
        }

        checked(
            "docker",
            &[
                "build",
                "-t",
                BACKEND_IMAGE,
                "-f",
                "tests/fixtures/backend.Dockerfile",
                "tests/fixtures",
            ],
            None,
            300,
        )?;
        checked(
            &self.env.k3d,
            &[
                "image",
                "import",
                &image,
                BACKEND_IMAGE,
                "--mode",
                "direct",
                "--cluster",
                &self.env.cluster,
            ],
            None,
            180,
        )?;
        self.helm_smoke()?;
        self.resources_created = true;

        for namespace in [&self.operator, &self.app] {
            self.env.apply(&json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": namespace,
                    "labels": {
                        "tunnellb.io/e2e": self.app,
                        "tunnellb.io/enabled": "true",
                        "pod-security.kubernetes.io/enforce": "privileged"
                    }
                }
            }))?;
        }

        let key = self.scratch.path().join("ssh-privatekey");
        fs::copy(&self.env.key, &key)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
        }

        self.env.kubectl(&[
            "-n",
            &self.operator,
            "create",
            "secret",
            "generic",
            "e2e-ssh",
            "--type=kubernetes.io/ssh-auth",
            &format!("--from-file=ssh-privatekey={}", key.display()),
        ])?;

        // Mark before installation so Drop also handles a partially failed release.
        self.installed = true;
        checked(
            "helm",
            &[
                "--kubeconfig",
                &self.env.kubeconfig,
                "--kube-context",
                &self.env.context,
                "install",
                "tunnellb",
                "charts/tunnellb",
                "--namespace",
                &self.operator,
                "--set",
                "createNamespace=false",
                "--set",
                "allowPrivateServers=true",
                "--set",
                "requeueSeconds=2",
                "--set-string",
                &format!("image.tag={}", self.image_tag),
                "--wait",
                "--timeout",
                "120s",
            ],
            None,
            150,
        )?;
        self.create_server()
    }

    pub(super) fn create_server(&self) -> Result<()> {
        self.env.apply(&json!({
            "apiVersion": "tunnellb.io/v1alpha1",
            "kind": "Server",
            "metadata": {
                "name": self.server,
                "labels": {"tunnellb.io/e2e": self.app}
            },
            "spec": {
                "address": self.env.address.to_string(),
                "ssh": {
                    "user": "root",
                    "port": 22,
                    "privateKeySecretRef": {"name": "e2e-ssh"}
                },
                "allowedNamespaces": [self.app]
            }
        }))?;

        Ok(())
    }

    fn helm_smoke(&mut self) -> Result<()> {
        eprintln!("e2e: default Helm installation into a fresh namespace");
        self.resources_created = true;
        self.installed = true;
        checked(
            "helm",
            &[
                "--kubeconfig",
                &self.env.kubeconfig,
                "--kube-context",
                &self.env.context,
                "upgrade",
                "--install",
                "tunnellb",
                "charts/tunnellb",
                "--namespace",
                &self.operator,
                "--create-namespace",
                "--set-string",
                &format!("image.tag={}", self.image_tag),
                "--wait",
                "--timeout",
                "120s",
            ],
            None,
            150,
        )?;
        let namespace = self
            .env
            .json(&["get", "namespace", &self.operator, "-o", "json"])?;
        ensure!(
            namespace["metadata"]["annotations"]["meta.helm.sh/release-name"] == "tunnellb"
                && namespace["metadata"]["annotations"]["meta.helm.sh/release-namespace"]
                    == self.operator
                && namespace["metadata"]["labels"]["pod-security.kubernetes.io/enforce"]
                    == "privileged",
            "default installation did not establish namespace ownership and worker admission"
        );

        self.cleanup()
    }

    pub(super) fn diagnostics(&self) {
        eprintln!("e2e: diagnostics in {}", self.scratch.path().display());

        for (name, args) in [
            (
                "pods",
                vec!["-n", &self.operator, "get", "pods", "-o", "json"],
            ),
            (
                "events",
                vec!["-n", &self.operator, "get", "events", "-o", "json"],
            ),
            (
                "services",
                vec!["-n", &self.app, "get", "services", "-o", "json"],
            ),
            ("server", vec!["get", "server", &self.server, "-o", "json"]),
            (
                "controller",
                vec![
                    "-n",
                    &self.operator,
                    "logs",
                    "deployment/tunnellb-controller",
                    "--tail=100",
                ],
            ),
        ] {
            if let Ok(bytes) = self.env.kubectl(&args) {
                let _ = fs::write(self.scratch.path().join(format!("{name}.log")), bytes);
            }
        }
    }

    pub(super) fn cleanup(&mut self) -> Result<()> {
        if !self.resources_created {
            return Ok(());
        }

        // Delete publications and the Server while their controller can perform
        // remote cleanup. Never strip finalizers or delete another run's objects.
        if self.installed {
            self.env
                .kubectl(&[
                    "-n",
                    &self.app,
                    "delete",
                    "services",
                    "--all",
                    "--ignore-not-found",
                    "--wait=true",
                    "--timeout=120s",
                ])
                .context("Service cleanup remains pending")?;
            self.env
                .kubectl(&[
                    "delete",
                    "server",
                    &self.server,
                    "--ignore-not-found",
                    "--wait=true",
                    "--timeout=150s",
                ])
                .context("Server cleanup remains pending")?;
            checked(
                "helm",
                &[
                    "--kubeconfig",
                    &self.env.kubeconfig,
                    "--kube-context",
                    &self.env.context,
                    "uninstall",
                    "tunnellb",
                    "--namespace",
                    &self.operator,
                    "--wait",
                    "--timeout",
                    "60s",
                ],
                None,
                90,
            )?;
            self.installed = false;
        }

        self.env.kubectl(&[
            "delete",
            "namespace",
            &self.app,
            &self.operator,
            "--ignore-not-found",
            "--wait=true",
            "--timeout=60s",
        ])?;
        self.resources_created = false;

        Ok(())
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        if !self.resources_created {
            return;
        }

        if !self.success {
            self.diagnostics();

            if enabled("TUNNELLB_E2E_KEEP_ON_FAILURE") {
                eprintln!(
                    "e2e: explicitly preserving failed namespaces {} / {} and Server {}",
                    self.operator, self.app, self.server
                );
                self.scratch.disable_cleanup(true);

                return;
            }
        }

        if let Err(error) = self.cleanup() {
            eprintln!(
                "e2e: {error}; retaining remaining resources in {} / {} for recovery",
                self.operator, self.app
            );
            self.scratch.disable_cleanup(true);
        }
    }
}
