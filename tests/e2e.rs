//! Requires an exclusively owned local k3d cluster and a fresh systemd edge.
//! TUNNELLB_E2E_ALLOW_DESTRUCTIVE=1 and TUNNELLB_E2E_KUBECONFIG are mandatory.
//! TUNNELLB_E2E_SKIP_BUILD=1 uses an existing operator image. Resources created
//! by the test are cleaned on exit; TUNNELLB_E2E_KEEP_ON_FAILURE=1 retains failed
//! runs for diagnosis. The prepared cluster and edge remain available afterward.
use anyhow::Result;

#[path = "fixtures/cluster.rs"]
mod cluster;
#[path = "fixtures/enrollment.rs"]
mod enrollment;
#[path = "fixtures/guard.rs"]
mod guard;
#[path = "fixtures/lifecycle.rs"]
mod lifecycle;
#[path = "fixtures/publication.rs"]
mod publication;
#[path = "fixtures/setup.rs"]
mod setup;

use cluster::Environment;
use setup::Run;

#[test]
#[ignore = "requires explicit destructive consent and a prepared disposable k3d/systemd environment"]
fn real_cluster_lifecycle() -> Result<()> {
    let mut run = Run::new(Environment::load()?)?;
    run.setup()?;
    run.enrollment()?;
    run.backend()?;
    eprintln!("e2e: real TCP and UDP forwarding");
    run.traffic(18080, 18081, false)?;
    run.guard()?;
    run.lifecycle()?;

    if cluster::enabled("TUNNELLB_E2E_HOLD_BEFORE_DELETE") {
        let resume = run.scratch.path().join("continue");
        eprintln!(
            "e2e: follow-up scenarios may run now; create {} to continue",
            resume.display()
        );
        cluster::wait_for("follow-up scenarios", 900, || Ok(resume.exists()))?;
    }

    run.deletion()?;
    run.cleanup()?;
    run.success = true;
    Ok(())
}
