use crate::{
    cluster::{Environment, text, wait_for},
    publication::{connect, exchange},
    setup::Run,
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use tunnellb::{
    api::{PortRange, Publication},
    provision::{self, AllocationOutcome, Operation, Request},
};

pub(super) fn run() -> Result<()> {
    let mut a = Run::new(Environment::load()?)?;
    let mut b = Run::new(Environment::load_second()?)?;
    ensure!(
        a.env.cluster != b.env.cluster && a.env.kubeconfig != b.env.kubeconfig,
        "the regression requires two independent clusters"
    );
    ensure!(
        a.env.edge == b.env.edge && a.env.address == b.env.address && a.env.key == b.env.key,
        "both clusters must share the same edge and SSH key"
    );
    let namespace_uid = |run: &Run| -> Result<Value> {
        Ok(run
            .env
            .json(&["get", "namespace", "kube-system", "-o", "json"])?["metadata"]["uid"]
            .clone())
    };
    ensure!(
        namespace_uid(&a)? != namespace_uid(&b)?,
        "kubeconfigs point to the same API server"
    );

    a.setup()?;
    a.enrollment()?;
    b.setup()?;
    b.enrollment()?;
    let uid_a = server_uid(&a)?;
    let uid_b = server_uid(&b)?;
    ensure!(uid_a != uid_b, "Server UIDs must differ across clusters");

    eprintln!("e2e: shared IPv4, shared SSH key, automatic default-range controls");
    a.backend_on(18080, 18081)?;
    b.backend_on(18180, 18181)?;
    let publication_a = publication(&a)?;
    let publication_b = publication(&b)?;
    let range = PortRange::default();
    ensure!(
        publication_a.control_port != publication_b.control_port,
        "independent clusters selected the same host control port"
    );
    eprintln!(
        "e2e: A UID {uid_a} control {}; B UID {uid_b} control {}",
        publication_a.control_port, publication_b.control_port
    );

    for (run, publication) in [(&a, &publication_a), (&b, &publication_b)] {
        ensure!(
            (range.start..=range.end).contains(&publication.control_port),
            "control allocation escaped the default range"
        );
        let service_uid = &publication.service.uid;
        ensure!(
            reserve_result(run, service_uid)?
                == Some(AllocationOutcome::Reserved {
                    control_port: publication.control_port,
                }),
            "persisted publication does not match the host Reserve result"
        );
    }

    a.traffic(18080, 18081, false)?;
    b.traffic(18180, 18181, false)?;
    conflicts(&a, &b)?;
    let stale_enrollment = saved_request(&a, Operation::Enroll)?;
    let stale_reservation = saved_request(&a, Operation::Reserve)?;

    eprintln!("e2e: deleting A preserves B's process, connector and established TCP stream");
    let unit_b = format!("tunnellb-{uid_b}@{}.service", publication_b.id);
    let process_before = process_identity(&b, &unit_b)?;
    let connector_before = b.connector("echo")?;
    let mut stream_b = connect(b.env.address, 18180)?;
    let first = exchange(&mut stream_b, "before-other-server-delete")?;
    let mut check_survivor = || -> Result<()> {
        let reply = exchange(&mut stream_b, "other-server-lifecycle")?;
        ensure!(
            reply["connection_id"] == first["connection_id"],
            "B's established TCP connection changed"
        );
        b.traffic(18180, 18181, false)
    };
    let binary_before = text(b.env.docker(&["sha256sum", "/opt/tunnellb/0.71.1/frps"])?)?;
    a.env
        .kubectl(&["delete", "server", &a.server, "--wait=false"])?;
    wait_for(
        "Server A deletion with uninterrupted B traffic",
        180,
        || {
            check_survivor()?;
            let servers = a.env.json(&["get", "servers", "-o", "json"])?;

            Ok(servers["items"]
                .as_array()
                .context("Server list missing")?
                .iter()
                .all(|server| server["metadata"]["uid"] != uid_a))
        },
    )?;
    retired(&a, &uid_a)?;
    ensure!(
        process_identity(&b, &unit_b)? == process_before,
        "deleting A restarted B's remote process"
    );
    ensure!(
        b.connector("echo")?["metadata"]["uid"] == connector_before["metadata"]["uid"],
        "deleting A replaced B's connector"
    );
    ensure!(
        text(b.env.docker(&["sha256sum", "/opt/tunnellb/0.71.1/frps"])?)? == binary_before,
        "deleting A changed the shared binary"
    );

    a.env
        .kubectl(&["-n", &a.app, "delete", "service", "echo", "--wait=false"])?;
    wait_for("old Service deletion", 120, || {
        check_survivor()?;
        let services = a
            .env
            .json(&["-n", &a.app, "get", "services", "-o", "json"])?;

        Ok(services["items"]
            .as_array()
            .context("Service list missing")?
            .iter()
            .all(|service| service["metadata"]["name"] != "echo"))
    })?;
    eprintln!("e2e: a new Server UID reuses A's numeric public ports");
    a.create_server()?;
    wait_for("replacement Server enrollment", 180, || {
        check_survivor()?;

        Ok(a.get(&a.operator, "server", &a.server)?["status"]["phase"] == "Ready")
    })?;
    let uid_c = server_uid(&a)?;
    ensure!(uid_c != uid_a && uid_c != uid_b);
    a.env.apply(&a.service("echo", 18080, 18081, false))?;
    a.published_while("echo", &mut check_survivor)?;
    let publication_c = publication(&a)?;
    ensure!(
        publication_c.server_uid == uid_c
            && publication_c.control_port != publication_b.control_port
            && (range.start..=range.end).contains(&publication_c.control_port)
    );
    ensure!(
        reserve_result(&a, &publication_c.service.uid)?
            == Some(AllocationOutcome::Reserved {
                control_port: publication_c.control_port,
            })
    );
    eprintln!(
        "e2e: C UID {uid_c} reused TCP 18080 / UDP 18081 with control {}",
        publication_c.control_port
    );
    a.traffic(18080, 18081, false)?;
    b.traffic(18180, 18181, false)?;
    eprintln!("e2e: old UID enrollment and reservation stay rejected after port reuse");
    let runtime = tokio::runtime::Runtime::new()?;

    for request in [&stale_enrollment, &stale_reservation] {
        // The shared binary is already installed and digest checked by the
        // worker; a stale request must be rejected without uploading an asset.
        let result = runtime.block_on(provision::run(request, &a.env.key, a.scratch.path()));
        let error = result
            .err()
            .context("retired Server UID accepted a stale request")?;
        ensure!(
            error.to_string().contains("Server UID was uninstalled"),
            "stale request failed without confirming terminal UID rejection: {error}"
        );
    }

    a.traffic(18080, 18081, false)?;
    b.traffic(18180, 18181, false)?;
    retired(&a, &uid_a)?;
    ensure!(
        process_identity(&b, &unit_b)? == process_before,
        "enrolling C restarted B's remote process"
    );
    ensure!(
        exchange(&mut stream_b, "after-port-reuse")?["connection_id"] == first["connection_id"],
        "B's established TCP connection did not survive C's publication"
    );
    unchanged_key(&a)?;

    a.cleanup()?;
    b.traffic(18180, 18181, false)?;
    ensure!(process_identity(&b, &unit_b)? == process_before);
    b.cleanup()?;
    retired(&a, &uid_a)?;
    retired(&a, &uid_c)?;
    retired(&b, &uid_b)?;
    unchanged_key(&a)?;
    a.env.docker(&["test", "-x", "/opt/tunnellb/0.71.1/frps"])?;
    a.success = true;
    b.success = true;
    eprintln!("e2e: shared-host regression passed and Kubernetes resources cleaned");

    Ok(())
}

fn conflicts(a: &Run, b: &Run) -> Result<()> {
    // The registry owns numeric ports, including TCP against an existing UDP
    // port and UDP against an existing TCP port in the other cluster.
    for (name, tcp, udp, conflict) in [
        ("same-protocol", 18080, 18182, 18080),
        ("udp-against-tcp", 18182, 18080, 18080),
        ("tcp-against-udp", 18081, 18182, 18081),
    ] {
        eprintln!("e2e: cross-cluster numeric conflict: {name}");
        b.env.apply(&b.service(name, tcp, udp, false))?;
        let uid = b.get(&b.app, "service", name)?["metadata"]["uid"]
            .as_str()
            .context("conflicting Service UID missing")?
            .to_owned();
        wait_for("host-global numeric port conflict", 180, || {
            Ok(b.get(&b.app, "service", name)?["status"]["conditions"]
                .as_array()
                .is_some_and(|conditions| {
                    conditions.iter().any(|condition| {
                        condition["type"] == "TunnelLBReady"
                            && condition["status"] == "False"
                            && condition["reason"] == "PortConflict"
                            && condition["message"].as_str().is_some_and(|message| {
                                message.contains(&format!("Public port {conflict} "))
                            })
                    })
                }))
        })?;
        let service = b.get(&b.app, "service", name)?;
        ensure!(
            service["status"]["loadBalancer"]["ingress"]
                .as_array()
                .is_none_or(Vec::is_empty),
            "conflicting Service received an ingress assignment"
        );
        ensure!(
            !service["status"]["conditions"]
                .as_array()
                .is_some_and(|conditions| conditions
                    .iter()
                    .any(|condition| condition["type"] == "TunnelLBReady"
                        && condition["status"] == "True")),
            "conflicting Service was reported ready"
        );
        ensure!(
            b.list(
                &b.operator,
                "deployments",
                &format!("tunnellb.io/service-uid={uid}")
            )?
            .is_empty(),
            "conflicting Service created a connector"
        );
        a.traffic(18080, 18081, false)?;
        b.traffic(18180, 18181, false)?;
        b.env.kubectl(&[
            "-n",
            &b.app,
            "delete",
            "service",
            name,
            "--wait=true",
            "--timeout=120s",
        ])?;
    }

    Ok(())
}

fn server_uid(run: &Run) -> Result<String> {
    Ok(
        run.get(&run.operator, "server", &run.server)?["metadata"]["uid"]
            .as_str()
            .context("Server UID missing")?
            .to_owned(),
    )
}

fn publication(run: &Run) -> Result<Publication> {
    let connector = run.connector("echo")?;
    let name = connector["metadata"]["name"]
        .as_str()
        .context("connector name missing")?;
    let record = run.get(&run.operator, "configmap", name)?;
    let record: Value = serde_json::from_str(
        record["data"]["record.json"]
            .as_str()
            .context("publication record missing")?,
    )?;

    Ok(serde_json::from_value(record["publication"].clone())?)
}

fn reserve_result(run: &Run, service_uid: &str) -> Result<Option<AllocationOutcome>> {
    let jobs = run.list(
        &run.operator,
        "jobs",
        &format!("tunnellb.io/server={}", run.server),
    )?;

    for job in jobs.iter().filter(|job| job["status"]["succeeded"] == 1) {
        let (request, outcome) = run.worker_result(job)?;

        if request["operation"] == "reserve"
            && request["publication"]["service"]["uid"] == service_uid
        {
            return Ok(outcome.allocation);
        }
    }

    Ok(None)
}

fn saved_request(run: &Run, operation: Operation) -> Result<Request> {
    let jobs = run.list(
        &run.operator,
        "jobs",
        &format!("tunnellb.io/server={}", run.server),
    )?;

    for job in jobs.iter().filter(|job| job["status"]["succeeded"] == 1) {
        let (request, _) = run.worker_result(job)?;
        let request: Request = serde_json::from_value(request)?;

        if request.operation == operation && request.expected_known_hosts.is_some() {
            return Ok(request);
        }
    }

    anyhow::bail!("successful pinned request missing")
}

fn process_identity(run: &Run, unit: &str) -> Result<String> {
    ensure!(text(run.env.docker(&["systemctl", "is-active", unit])?)? == "active");
    let identity = text(run.env.docker(&[
        "systemctl",
        "show",
        unit,
        "--property=MainPID,ExecMainStartTimestampMonotonic",
    ])?)?;
    ensure!(
        !identity.lines().any(|line| line == "MainPID=0"),
        "B has no live process"
    );

    Ok(identity)
}

fn retired(run: &Run, uid: &str) -> Result<()> {
    ensure!(
        text(
            run.env
                .docker(&["cat", &format!("/var/lib/tunnellb/retired/{uid}")])?
        )? == uid,
        "terminal UID tombstone missing"
    );
    run.env
        .docker(&["test", "!", "-e", &format!("/var/lib/tunnellb/{uid}")])?;
    run.env.docker(&[
        "test",
        "!",
        "-e",
        &format!("/etc/systemd/system/tunnellb-{uid}@.service"),
    ])?;

    Ok(())
}

fn unchanged_key(run: &Run) -> Result<()> {
    ensure!(
        text(
            run.env
                .docker(&["sha256sum", "/root/.ssh/authorized_keys"])?
        )? == run.env.authorized_keys_digest,
        "shared-host operations changed the original authorized SSH key"
    );

    Ok(())
}
