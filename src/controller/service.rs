use crate::{
    api::{CLASS, Machine, Publication, SERVICE_UID_LABEL, ServiceRequest},
    store::PublicationRecord,
    validation,
};
use anyhow::{Context as _, Result};
use k8s_openapi::api::{
    apps::v1::Deployment,
    core::v1::{Namespace, Node, Pod, Service},
    discovery::v1::EndpointSlice,
};
use kube::{
    Api, ResourceExt,
    api::{ListParams, Patch, PatchParams},
    runtime::controller::Action,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::Ipv4Addr, sync::Arc};

use super::{
    Context, ReconcileError,
    kubernetes::{force_delete, has_finalizer, set_finalizer},
    publication::{
        cleanup_publication, connector_matches, ensure_publication, publication_hash,
        publication_id, terminate_connector,
    },
    reservation::ReservationConflict,
};

pub(super) async fn reconcile_service(
    service: Arc<Service>,
    context: Arc<Context>,
) -> Result<Action, ReconcileError> {
    let _lock = context.serial.lock().await;
    match service_inner(&service, &context).await {
        Ok(()) => Ok(if is_managed(&service) || has_finalizer(service.as_ref()) {
            context.action()
        } else {
            Action::await_change()
        }),
        Err(_) => {
            let _ = service_condition(
                &service,
                &context,
                false,
                "ReconcileFailed",
                "Operation failed and will retry; check Machine and SSH Job state.",
                None,
            )
            .await;
            Err(ReconcileError)
        }
    }
}

pub(super) async fn service_inner(service: &Service, context: &Context) -> Result<()> {
    let managed = is_managed(service);
    let namespace = service.namespace().context("Service namespace missing")?;
    let uid = service.uid().context("Service UID missing")?;
    let services: Api<Service> = Api::namespaced(context.client.clone(), &namespace);
    let mut records = context
        .store
        .records(&format!("{SERVICE_UID_LABEL}={uid}"))
        .await?;

    if !managed && !has_finalizer(service) && records.is_empty() {
        return Ok(());
    }

    if service.metadata.deletion_timestamp.is_some() || !managed {
        let mut complete = true;
        for record in &records {
            complete &= cleanup_publication(record, context, false).await?;
        }

        // Tenant abandonment can detach the Service, never its port lease.
        if !complete && force_delete(service) {
            let mut stopped = true;
            for record in &records {
                stopped &= terminate_connector(&record.publication, context).await?;
            }

            if stopped {
                set_finalizer(&services, service, false).await?;
            }

            return Ok(());
        }

        if complete {
            if service.metadata.deletion_timestamp.is_none() {
                service_condition(
                    service,
                    context,
                    false,
                    "Removed",
                    "Tunnel publication removed.",
                    Some(vec![]),
                )
                .await?;
            }

            set_finalizer(&services, service, false).await?;
        }

        return Ok(());
    }

    if records.iter().any(|r| r.removing) {
        for record in records.iter().filter(|r| r.removing) {
            cleanup_publication(record, context, false).await?;
        }

        return service_condition(
            service,
            context,
            false,
            "Reconfiguring",
            "Finishing committed cleanup before creating a replacement publication.",
            None,
        )
        .await;
    }

    if !has_finalizer(service) {
        set_finalizer(&services, service, true).await?;

        return Ok(());
    }

    let ns = Api::<Namespace>::all(context.client.clone())
        .get(&namespace)
        .await?;
    let request = match validation::service_request(service, &ns) {
        Ok(request) => request,
        Err(error) => {
            for record in &records {
                terminate_connector(&record.publication, context).await?;
            }

            return service_condition(
                service,
                context,
                false,
                "InvalidService",
                &error.to_string(),
                Some(published_ips(&records)),
            )
            .await;
        }
    };
    // Read the complete set; label selectors alone must not hide manual slices.
    let slices = Api::<EndpointSlice>::namespaced(context.client.clone(), &namespace)
        .list(
            &ListParams::default().labels(&format!("kubernetes.io/service-name={}", request.name)),
        )
        .await?;
    let pods = Api::<Pod>::namespaced(context.client.clone(), &namespace)
        .list(&ListParams::default())
        .await?;
    let backends = validation::validate_backends(&request, service, &slices.items, &pods.items);
    let unavailable = backends.as_ref().is_err_and(|error| {
        error
            .downcast_ref::<validation::ValidationError>()
            .is_some_and(validation::ValidationError::is_backend_unavailable)
    });

    if let Err(error) = &backends
        && !unavailable
    {
        for record in &records {
            terminate_connector(&record.publication, context).await?;
        }

        return service_condition(
            service,
            context,
            false,
            "BackendNotVerified",
            &error.to_string(),
            Some(published_ips(&records)),
        )
        .await;
    }

    let mut machines = Api::<Machine>::all(context.client.clone())
        .list(&ListParams::default())
        .await?
        .items;
    machines.sort_by_key(ResourceExt::name_any);
    let nodes = Api::<Node>::all(context.client.clone())
        .list(&ListParams::default())
        .await?
        .items;

    if !reconcile_assignments(
        service,
        &mut records,
        &request,
        &machines,
        &nodes,
        unavailable,
        context,
    )
    .await?
    {
        return Ok(());
    }

    let requested = usize::from(request.replicas);

    let backend_ports = match backends {
        Ok(ports) => ports,
        Err(error) => {
            return service_condition(
                service,
                context,
                false,
                "BackendUnavailable",
                &error.to_string(),
                Some(published_ips(&records)),
            )
            .await;
        }
    };

    for machine in &machines {
        if records.len() >= requested {
            break;
        }

        if machine.status.as_ref().is_none_or(|s| s.phase != "Ready")
            || duplicate_address(machine, &machines)
            || records
                .iter()
                .any(|r| r.publication.machine_uid == machine.uid().unwrap_or_default())
        {
            continue;
        }

        let Some(address) = eligible_address(
            machine,
            &request,
            &nodes,
            context.config.allow_private_machines,
        ) else {
            continue;
        };
        let machine_uid = machine.uid().context("Machine UID missing")?;
        let id = publication_id(&uid, &machine_uid);
        let control_port = match context
            .store
            .allocate_unpublished(machine, &request, &id)
            .await
        {
            Ok(port) => port,
            Err(error) if error.is::<crate::allocation::AllocationConflict>() => continue,
            Err(error) => return Err(error),
        };
        let publication = Publication {
            id,
            machine_name: machine.name_any(),
            machine_uid,
            machine_address: address,
            control_port,
            service: request.clone(),
        };
        let record = PublicationRecord {
            config_hash: publication_hash(&publication, &context.resources)?,
            publication,
            machine_spec: machine.spec.clone(),
            backend_ports: backend_ports.clone(),
            applied_hash: None,
            published: false,
            removing: false,
            credential_generation: None,
            reserved: false,
        };
        context.store.save_record(&record).await?;
        records.push(record);
    }

    let mut ready = records.len() == requested;
    let mut conflict = None;
    for record in &mut records {
        let machine = machines
            .iter()
            .find(|m| m.uid().as_deref() == Some(record.publication.machine_uid.as_str()))
            .context("assigned Machine missing")?;
        // NetworkPolicy follows targetPort changes. The client still dials the
        // same ClusterIP and does not restart for ordinary backend Pod churn.
        let previous_hash = publication_hash(&record.publication, &context.resources)?;
        record.publication.service = request.clone();
        record.backend_ports = backend_ports.clone();
        record.machine_spec = machine.spec.clone();
        record.config_hash = publication_hash(&record.publication, &context.resources)?;

        // Names and PROXY mode affect only frpc. The allocation check above
        // guarantees that frps's immutable configuration remains unchanged.
        if record.applied_hash.as_ref() == Some(&previous_hash) {
            record.applied_hash = Some(record.config_hash.clone());
        }

        context.store.save_record(record).await?;
        match ensure_publication(record, machine, context).await {
            Ok(published) => ready &= published,
            Err(error) => match error.downcast::<ReservationConflict>() {
                Ok(reason) => {
                    ready = false;
                    conflict = Some(reason);
                }
                Err(error) => return Err(error),
            },
        }
    }

    if let Some(conflict) = conflict {
        return service_condition(
            service,
            context,
            false,
            conflict.reason(),
            &conflict.to_string(),
            Some(published_ips(&records)),
        )
        .await;
    }

    let reason = if ready {
        "Published"
    } else if records.len() < requested {
        "AllocationPending"
    } else {
        "Connecting"
    };
    let message = if ready {
        "Every requested edge has registered the publication."
    } else if records.len() < requested {
        "Waiting for an eligible ready Machine with free ports."
    } else {
        "Waiting for remote provisioning or tunnel registration; previously published addresses are retained."
    };
    service_condition(
        service,
        context,
        ready,
        reason,
        message,
        Some(published_ips(&records)),
    )
    .await
}

// Return false while an existing assignment is being revoked or suspended.
async fn reconcile_assignments(
    service: &Service,
    records: &mut [PublicationRecord],
    request: &ServiceRequest,
    machines: &[Machine],
    nodes: &[Node],
    unavailable: bool,
    context: &Context,
) -> Result<bool> {
    // Existing selections persist unless an explicit selector excludes them.
    let mut removing = false;
    let mut address_conflict = false;
    for record in records.iter() {
        let machine = machines
            .iter()
            .find(|m| m.uid().as_deref() == Some(record.publication.machine_uid.as_str()));
        let eligible = machine.and_then(|m| {
            eligible_address(m, request, nodes, context.config.allow_private_machines)
        }) == Some(record.publication.machine_address);
        let duplicate = machine.is_some_and(|m| duplicate_address(m, machines));

        if !eligible || !same_allocation(&record.publication.service, request) {
            removing = true;
            cleanup_publication(record, context, false).await?;
        } else if duplicate || (unavailable && record.publication.service.ports != request.ports) {
            // A duplicate suspends this assignment without surrendering its lease.
            // Only an unchanged, verified destination may survive unavailability.
            address_conflict |= duplicate;
            terminate_connector(&record.publication, context).await?;
        } else if unavailable {
            let deployment = context
                .api::<Deployment>()
                .get_opt(&record.publication.id)
                .await?;

            // Desired fields may have been saved immediately before a crash.
            // Unavailability must not preserve a still-running older template.
            if !deployment
                .as_ref()
                .is_some_and(|d| connector_matches(d, &record.config_hash))
            {
                terminate_connector(&record.publication, context).await?;
            }
        }
    }

    if removing {
        service_condition(
            service,
            context,
            false,
            "Reconfiguring",
            "Stopping the previous publication before changing its destination or assignment.",
            None,
        )
        .await?;

        return Ok(false);
    }

    if address_conflict {
        service_condition(
            service,
            context,
            false,
            "AddressConflict",
            "An assigned Machine shares its address; connectors are stopped and assignments retained.",
            Some(published_ips(records)),
        )
        .await?;

        return Ok(false);
    }

    let requested = usize::from(request.replicas);

    if records.len() > requested {
        records.sort_by_key(|r| r.publication.machine_name.clone());
        for record in &records[requested..] {
            cleanup_publication(record, context, false).await?;
        }

        service_condition(
            service,
            context,
            false,
            "Reconfiguring",
            "Removing surplus edge publications.",
            None,
        )
        .await?;

        return Ok(false);
    }

    Ok(true)
}

fn same_allocation(previous: &ServiceRequest, next: &ServiceRequest) -> bool {
    let bindings = |request: &ServiceRequest| {
        request
            .ports
            .iter()
            .map(|port| (port.protocol, port.port))
            .collect::<BTreeSet<_>>()
    };
    previous.cluster_ip == next.cluster_ip
        && previous.selector == next.selector
        && bindings(previous) == bindings(next)
}

fn eligible_address(
    machine: &Machine,
    request: &ServiceRequest,
    nodes: &[Node],
    allow_private: bool,
) -> Option<Ipv4Addr> {
    if !machine_permitted(machine, request) || machine.metadata.deletion_timestamp.is_some() {
        return None;
    }

    validation::validate_machine(machine, nodes, allow_private).ok()
}

fn duplicate_address(machine: &Machine, machines: &[Machine]) -> bool {
    machines
        .iter()
        .filter(|other| other.spec.address == machine.spec.address)
        .count()
        > 1
}

pub(super) fn machine_permitted(machine: &Machine, service: &ServiceRequest) -> bool {
    (machine.spec.allowed_namespaces.is_empty()
        || machine.spec.allowed_namespaces.contains(&service.namespace))
        && (service.machines.is_empty() || service.machines.contains(&machine.name_any()))
        && (service.pool.is_none() || machine.spec.pool == service.pool)
}

pub(super) fn is_managed(service: &Service) -> bool {
    service.spec.as_ref().is_some_and(|s| {
        s.type_.as_deref() == Some("LoadBalancer")
            && s.load_balancer_class.as_deref() == Some(CLASS)
    })
}

pub(super) fn published_ips(records: &[PublicationRecord]) -> Vec<String> {
    records
        .iter()
        .filter(|r| r.published)
        .map(|r| r.publication.machine_address.to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) async fn service_condition(
    service: &Service,
    context: &Context,
    ready: bool,
    reason: &str,
    message: &str,
    ips: Option<Vec<String>>,
) -> Result<()> {
    let state = if ready { "True" } else { "False" };
    let previous = service
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| cs.iter().find(|c| c.type_ == "TunnelLBReady"));
    let transition = previous
        .filter(|c| c.status == state)
        .map(|c| c.last_transition_time.0.to_string())
        .unwrap_or_else(|| k8s_openapi::jiff::Timestamp::now().to_string());
    let mut conditions: Vec<Value> = service
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .into_iter()
        .flatten()
        .filter(|c| c.type_ != "TunnelLBReady")
        .map(serde_json::to_value)
        .collect::<std::result::Result<_, _>>()?;
    conditions.push(json!({
        "type": "TunnelLBReady", "status": state, "reason": reason, "message": message,
        "observedGeneration": service.metadata.generation.unwrap_or(0),
        "lastTransitionTime": transition,
    }));
    let mut status = json!({"conditions": conditions});

    if let Some(ips) = ips {
        status["loadBalancer"] = json!({"ingress": ips.into_iter().map(|ip| json!({"ip":ip,"ipMode":"Proxy"})).collect::<Vec<_>>()});
    }

    let current = serde_json::to_value(&service.status)?;

    if status.as_object().is_some_and(|fields| {
        fields
            .iter()
            .all(|(key, value)| current.get(key) == Some(value))
    }) {
        return Ok(());
    }

    let api: Api<Service> = Api::namespaced(
        context.client.clone(),
        &service.namespace().unwrap_or_default(),
    );
    api.patch_status(
        &service.name_any(),
        &PatchParams::apply("tunnellb"),
        &Patch::Merge(json!({"metadata": {"uid": service.uid(), "resourceVersion": service.resource_version()}, "status": status})),
    )
    .await?;
    Ok(())
}
