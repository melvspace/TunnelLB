use k8s_openapi::api::core::v1::{Namespace, Service};
use serde_json::{Value, json};

use crate::api::{CLASS, ENABLED_LABEL};

pub(super) fn namespace() -> Namespace {
    serde_json::from_value(json!({
        "metadata": {"name": "apps", "labels": {ENABLED_LABEL: "true"}}
    }))
    .unwrap()
}

pub(super) fn service_value() -> Value {
    json!({
        "metadata": {"name": "web", "namespace": "apps", "uid": "service-uid"},
        "spec": {
            "type": "LoadBalancer", "loadBalancerClass": CLASS,
            "allocateLoadBalancerNodePorts": false,
            "clusterIP": "10.96.0.10", "clusterIPs": ["10.96.0.10"],
            "selector": {"app": "web"},
            "ports": [{"name": "http", "port": 80, "protocol": "TCP", "targetPort": 8080}]
        }
    })
}

pub(super) fn service() -> Service {
    serde_json::from_value(service_value()).unwrap()
}
