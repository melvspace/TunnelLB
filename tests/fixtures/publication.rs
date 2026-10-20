use crate::{
    cluster::wait_for,
    setup::{BACKEND_IMAGE, Run},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    time::Duration,
};

impl Run {
    pub(super) fn backend(&self) -> Result<()> {
        self.env.apply(&json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "backend",
                "namespace": self.app
            },
            "spec": {
                "replicas": 2,
                "strategy": {
                    "type": "RollingUpdate",
                    "rollingUpdate": {
                        "maxUnavailable": 0,
                        "maxSurge": 1
                    }
                },
                "selector": {
                    "matchLabels": {
                        "app": "e2e-backend"
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": "e2e-backend"
                        }
                    },
                    "spec": {
                        "automountServiceAccountToken": false,
                        "securityContext": {
                            "runAsNonRoot": true,
                            "runAsUser": 10001,
                            "runAsGroup": 10001,
                            "seccompProfile": {
                                "type": "RuntimeDefault"
                            }
                        },
                        "containers": [
                            {
                                "name": "backend",
                                "image": BACKEND_IMAGE,
                                "imagePullPolicy": "Never",
                                "securityContext": {
                                    "allowPrivilegeEscalation": false,
                                    "readOnlyRootFilesystem": true,
                                    "capabilities": {
                                        "drop": ["ALL"]
                                    }
                                },
                                "ports": [
                                    {
                                        "name": "tcp",
                                        "containerPort": 8080
                                    },
                                    {
                                        "name": "udp",
                                        "containerPort": 8081,
                                        "protocol": "UDP"
                                    },
                                    {
                                        "name": "health",
                                        "containerPort": 8082
                                    }
                                ],
                                "resources": {
                                    "requests": {
                                        "cpu": "25m",
                                        "memory": "32Mi"
                                    },
                                    "limits": {
                                        "cpu": "250m",
                                        "memory": "128Mi"
                                    }
                                },
                                "readinessProbe": {
                                    "httpGet": {
                                        "path": "/healthz",
                                        "port": "health"
                                    },
                                    "periodSeconds": 1
                                },
                                "livenessProbe": {
                                    "httpGet": {
                                        "path": "/healthz",
                                        "port": "health"
                                    },
                                    "periodSeconds": 5
                                }
                            }
                        ]
                    }
                }
            }
        }))?;

        self.env.kubectl(&[
            "-n",
            &self.app,
            "rollout",
            "status",
            "deployment/backend",
            "--timeout=120s",
        ])?;

        self.env.apply(&self.service("echo", 18080, 18081, false))?;
        self.published("echo")
    }

    pub(super) fn service(&self, name: &str, tcp: u16, udp: u16, proxy: bool) -> Value {
        json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": name,
                "namespace": self.app,
                "annotations": if proxy {
                    json!({
                        "tunnellb.io/proxy-protocol": "tcp=v2"
                    })
                } else {
                    json!({})
                }
            },
            "spec": {
                "type": "LoadBalancer",
                "loadBalancerClass": "tunnellb.io/edge",
                "allocateLoadBalancerNodePorts": false,
                "selector": {
                    "app": "e2e-backend"
                },
                "ports": [
                    {
                        "name": "tcp",
                        "protocol": "TCP",
                        "port": tcp,
                        "targetPort": "tcp"
                    },
                    {
                        "name": "udp",
                        "protocol": "UDP",
                        "port": udp,
                        "targetPort": "udp"
                    }
                ]
            }
        })
    }

    pub(super) fn published(&self, name: &str) -> Result<()> {
        wait_for("Service publication", 180, || {
            let service = self.get(&self.app, "service", name)?;

            Ok(service["status"]["conditions"]
                .as_array()
                .is_some_and(|cs| {
                    cs.iter()
                        .any(|c| c["type"] == "TunnelLBReady" && c["status"] == "True")
                }))
        })?;

        let service = self.get(&self.app, "service", name)?;
        ensure!(
            service["status"]["loadBalancer"]["ingress"]
                == json!([
                    {
                        "ip": self.env.address.to_string(),
                        "ipMode": "Proxy"
                    }
                ]),
            "unexpected ingress assignment or IP mode"
        );

        Ok(())
    }

    pub(super) fn connector(&self, service: &str) -> Result<Value> {
        let uid = self.get(&self.app, "service", service)?["metadata"]["uid"]
            .as_str()
            .context("Service UID missing")?
            .to_owned();
        let deployments = self.list(
            &self.operator,
            "deployments",
            &format!("tunnellb.io/service-uid={uid}"),
        )?;

        ensure!(
            deployments.len() == 1,
            "default assignment must create exactly one connector"
        );
        ensure!(
            deployments[0]["metadata"]["labels"]["tunnellb.io/machine"] == self.machine,
            "default assignment picked the wrong Machine"
        );

        Ok(deployments[0].clone())
    }

    pub(super) fn traffic(&self, tcp: u16, udp: u16, proxy: bool) -> Result<()> {
        let mut connection = connect(self.env.address, tcp)?;
        let local = connection.local_addr()?;
        let reply = exchange(&mut connection, "tunnellb-tcp")?;

        ensure!(reply["payload"] == "tunnellb-tcp", "TCP payload changed");
        ensure!(
            reply["proxy_version"] == if proxy { json!(2) } else { Value::Null },
            "unexpected PROXY framing"
        );

        if proxy {
            ensure!(
                reply["proxy_source"]["ip"] == local.ip().to_string()
                    && reply["proxy_source"]["port"] == local.port(),
                "PROXY v2 source tuple mismatch"
            );
        }

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        socket.connect((self.env.address, udp))?;
        socket.send(b"tunnellb-udp")?;

        let mut bytes = [0u8; 4096];
        let len = socket.recv(&mut bytes)?;
        let response: Value = serde_json::from_slice(&bytes[..len])?;
        ensure!(response["payload"] == "tunnellb-udp", "UDP payload changed");

        Ok(())
    }
}

pub(super) fn connect(address: Ipv4Addr, port: u16) -> Result<TcpStream> {
    let stream =
        TcpStream::connect_timeout(&SocketAddr::from((address, port)), Duration::from_secs(3))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;

    Ok(stream)
}

pub(super) fn exchange(stream: &mut TcpStream, payload: &str) -> Result<Value> {
    stream.write_all(payload.as_bytes())?;
    stream.write_all(b"\n")?;

    let mut line = String::new();
    let count = BufReader::new(stream).take(8192).read_line(&mut line)?;

    if count == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
    }

    ensure!(line.ends_with('\n'), "backend response exceeded the bound");

    Ok(serde_json::from_str(&line)?)
}
