use crate::{api::Machine, resources::ResourceOptions, store::Store};
use anyhow::{Result, ensure};
use clap::Args;
use futures::StreamExt;
use k8s_openapi::api::{
    core::v1::{Namespace, Pod, Service},
    discovery::v1::EndpointSlice,
};
use kube::{
    Api, Client, Resource, ResourceExt,
    api::ListParams,
    runtime::{Controller, controller::Action, reflector::ObjectRef, watcher},
};
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex;

mod health;
mod kubernetes;
mod machine;
mod publication;
mod reservation;
mod service;
use health::serve_health;
use machine::reconcile_machine;
use publication::cleanup_publication;
pub use publication::publication_id;
use service::{is_managed, reconcile_service};

#[derive(Args, Clone, Debug)]
pub struct Config {
    #[arg(long, env = "TUNNELLB_NAMESPACE", default_value = "tunnellb-system")]
    pub namespace: String,
    #[arg(long, env = "TUNNELLB_IMAGE", default_value = "tunnellb:0.1.0")]
    pub image: String,
    #[arg(
        long,
        env = "TUNNELLB_IMAGE_PULL_POLICY",
        default_value = "IfNotPresent"
    )]
    pub image_pull_policy: String,
    #[arg(
        long,
        env = "TUNNELLB_WORKER_SERVICE_ACCOUNT",
        default_value = "tunnellb-worker"
    )]
    pub worker_service_account: String,
    #[arg(long, env = "TUNNELLB_ALLOW_PRIVATE_MACHINES", default_value_t = false)]
    pub allow_private_machines: bool,
    #[arg(long, env = "TUNNELLB_REQUEUE_SECONDS", default_value_t = 10)]
    pub requeue_seconds: u64,
    #[arg(long, env = "TUNNELLB_HEALTH_ADDRESS", default_value = "0.0.0.0:8080")]
    pub health_address: SocketAddr,
}

struct Context {
    client: Client,
    store: Store,
    config: Config,
    resources: ResourceOptions,
    // The chart runs one replica. Serializing both controllers makes multi-step
    // local transitions deterministic; persisted ledgers additionally use CAS.
    serial: Mutex<()>,
}

#[derive(Debug, thiserror::Error)]
#[error("reconciliation failed; see the resource's TunnelLB condition")]
struct ReconcileError;

pub async fn run(config: Config) -> Result<()> {
    ensure!(
        config.requeue_seconds > 0,
        "requeue seconds must be positive"
    );
    let client = Client::try_default().await?;
    let context = Arc::new(Context {
        store: Store::new(client.clone(), config.namespace.clone()),
        resources: ResourceOptions {
            namespace: config.namespace.clone(),
            image: config.image.clone(),
            pull_policy: config.image_pull_policy.clone(),
            service_account: config.worker_service_account.clone(),
        },
        client: client.clone(),
        config: config.clone(),
        serial: Mutex::new(()),
    });
    // Fail startup on missing CRDs/RBAC, instead of reporting a healthy idle loop.
    Api::<Machine>::all(client.clone())
        .list(&ListParams::default().limit(1))
        .await?;
    Api::<Service>::all(client.clone())
        .list(&ListParams::default().limit(1))
        .await?;
    let healthy = Arc::new(AtomicBool::new(true));
    let health = tokio::spawn(serve_health(
        config.health_address,
        healthy.clone(),
        client.clone(),
        config.namespace.clone(),
    ));

    let controller = Controller::new(
        Api::<Service>::all(client.clone()),
        watcher::Config::default(),
    );
    let service_cache = controller.store();
    let pod_cache = service_cache.clone();
    let namespace_cache = service_cache.clone();
    let machine_cache = service_cache.clone();
    let services = controller
        .watches(
            Api::<EndpointSlice>::all(client.clone()),
            watcher::Config::default(),
            |slice| {
                slice
                    .labels()
                    .get("kubernetes.io/service-name")
                    .map(|name| ObjectRef::new(name).within(&slice.namespace().unwrap_or_default()))
            },
        )
        .watches(
            Api::<Pod>::all(client.clone()),
            watcher::Config::default(),
            move |pod| {
                pod_cache
                    .state()
                    .into_iter()
                    .filter(|service| is_managed(service) && service.namespace() == pod.namespace())
                    .map(|service| ObjectRef::from_obj(service.as_ref()))
                    .collect::<Vec<_>>()
            },
        )
        .watches(
            Api::<Namespace>::all(client.clone()),
            watcher::Config::default(),
            move |ns| {
                namespace_cache
                    .state()
                    .into_iter()
                    .filter(|service| {
                        is_managed(service) && {
                            service.namespace().as_deref() == Some(ns.name_any().as_str())
                        }
                    })
                    .map(|service| ObjectRef::from_obj(service.as_ref()))
                    .collect::<Vec<_>>()
            },
        )
        .watches(
            Api::<Machine>::all(client.clone()),
            watcher::Config::default(),
            move |_| {
                machine_cache
                    .state()
                    .into_iter()
                    .filter(|service| is_managed(service))
                    .map(|service| ObjectRef::from_obj(service.as_ref()))
                    .collect::<Vec<_>>()
            },
        )
        .shutdown_on_signal()
        .run(reconcile_service, error_policy, context.clone())
        .for_each(|result| async move {
            if result.is_err() {
                tracing::warn!("Service reconciliation will retry");
            }
        });
    let sweep = sweep_orphans(context.clone());
    let machines = Controller::new(Api::<Machine>::all(client), watcher::Config::default())
        .shutdown_on_signal()
        .run(reconcile_machine, error_policy, context)
        .for_each(|result| async move {
            if result.is_err() {
                tracing::warn!("Machine reconciliation will retry");
            }
        });
    tokio::select! {
        _ = services => {},
        _ = machines => {},
        _ = sweep => {},
        result = health => { result??; }
    }

    healthy.store(false, Ordering::Relaxed);
    Ok(())
}

async fn sweep_orphans(context: Arc<Context>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        let _lock = context.serial.lock().await;

        if sweep_once(&context).await.is_err() {
            tracing::warn!("Orphan publication cleanup will retry");
        }
    }
}

async fn sweep_once(context: &Context) -> Result<()> {
    let services = Api::<Service>::all(context.client.clone())
        .list(&ListParams::default())
        .await?;
    let machines = Api::<Machine>::all(context.client.clone())
        .list(&ListParams::default())
        .await?;
    let records = context.store.records("").await?;
    for record in &records {
        let service_live = services.items.iter().any(|s| {
            is_managed(s) && s.uid().as_deref() == Some(record.publication.service.uid.as_str())
        });
        let machine_live = machines
            .items
            .iter()
            .any(|m| m.uid().as_deref() == Some(record.publication.machine_uid.as_str()));

        if (record.removing || !service_live || !machine_live)
            && cleanup_publication(record, context, false).await.is_err()
        {
            tracing::warn!(publication = %record.publication.id, "Orphan cleanup will retry");
        }
    }

    for machine in &machines.items {
        let Some(uid) = machine.uid() else {
            continue;
        };
        // Preserve reservation-only writes for live Services and every record
        // whose remote cleanup has not completed.
        let mut live: BTreeSet<_> = services
            .items
            .iter()
            .filter_map(ResourceExt::uid)
            .map(|service_uid| publication_id(&service_uid, &uid))
            .collect();
        live.extend(
            records
                .iter()
                .filter(|r| r.publication.machine_uid == uid)
                .map(|r| r.publication.id.clone()),
        );

        if context.store.gc_allocations(&uid, &live).await.is_err() {
            tracing::warn!(machine = %machine.name_any(), "Allocation cleanup will retry");
        }
    }

    Ok(())
}

fn error_policy<K>(_: Arc<K>, _: &ReconcileError, context: Arc<Context>) -> Action {
    Action::requeue(Duration::from_secs(context.config.requeue_seconds))
}

impl Context {
    fn action(&self) -> Action {
        Action::requeue(Duration::from_secs(self.config.requeue_seconds))
    }

    fn api<K>(&self) -> Api<K>
    where
        K: Resource<DynamicType = (), Scope = kube::core::NamespaceResourceScope>,
    {
        Api::namespaced(self.client.clone(), &self.config.namespace)
    }

    fn revision(&self, purpose: &str) -> String {
        // A failed immutable Job is retried in the next bucket. Successful apply
        // results are persisted, so this never periodically rolls healthy pods.
        format!(
            "{}:{}:{}:{}",
            purpose,
            self.config.image,
            self.resources.pull_policy,
            k8s_openapi::jiff::Timestamp::now().as_second() / 600
        )
    }
}

#[cfg(test)]
mod tests;
