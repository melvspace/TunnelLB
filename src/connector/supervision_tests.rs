use std::{fs, path::PathBuf};

use super::*;

#[tokio::test]
async fn oversized_logs_are_bounded() {
    let bytes = vec![b'x'; MAX_LOG_BYTES + 10];
    let mut reader = BufReader::new(bytes.as_slice());
    assert!(bounded_line(&mut reader).await.is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn spawned_child_uses_separate_group_and_dies_on_drop() {
    let mut command = Command::new("/bin/sleep");
    command.arg("60");
    let process = Process::spawn(command).unwrap();
    let pid = process.pid;
    // A separately supervised process group is necessary for bounded
    // termination, and prevents signalling the test runner.
    assert_eq!(unsafe { libc::getpgid(pid) }, pid);
    drop(process);

    for _ in 0..100 {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            return;
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    panic!("child survived supervisor drop");
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "subprocess fixture invoked by supervision tests"]
async fn signal_fixture() {
    let directory = PathBuf::from(std::env::var_os("TUNNELLB_TEST_PROCESS_DIR").unwrap());

    if std::env::var_os("TUNNELLB_TEST_PARENT_DEATH").is_some() {
        let mut command = Command::new("/bin/sleep");
        command.arg("60");
        let process = Process::spawn(command).unwrap();
        fs::write(directory.join("child-pid"), process.pid.to_string()).unwrap();
        std::future::pending::<()>().await;
    }

    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg(
        "trap 'printf TERM > \"$TUNNELLB_TEST_PROCESS_DIR/received\"; exit 0' TERM; \
         trap 'printf INT > \"$TUNNELLB_TEST_PROCESS_DIR/received\"; exit 0' INT; \
         printf started > \"$TUNNELLB_TEST_PROCESS_DIR/started\"; \
         while :; do sleep 1; done",
    );
    let markers = HealthMarkers::new(&directory.join("ready")).unwrap();
    let registrations = Registrations::from_config(
        "log.to='console'\nlog.level='debug'\nlog.disablePrintColor=true\n[[proxies]]\nname='signal-test'\ntype='tcp'"
    ).unwrap();
    supervise(command, registrations, markers).await.unwrap();
}

#[cfg(target_os = "linux")]
async fn wait_for_file(path: &Path) {
    timeout(Duration::from_secs(10), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("subprocess did not become ready");
}

#[cfg(target_os = "linux")]
fn fixture(directory: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "connector::supervision::tests::signal_fixture",
            "--ignored",
            "--nocapture",
        ])
        .env("TUNNELLB_TEST_PROCESS_DIR", directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn supervisor_forwards_term_and_int() {
    fs::create_dir_all("/tmp/codex").unwrap();

    for (signal, expected) in [(libc::SIGTERM, "TERM"), (libc::SIGINT, "INT")] {
        let directory = tempfile::tempdir_in("/tmp/codex").unwrap();
        let mut child = fixture(directory.path()).spawn().unwrap();
        wait_for_file(&directory.path().join("started")).await;

        let pid = child.id().unwrap() as i32;
        assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
        let status = timeout(Duration::from_secs(10), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(
            status.success(),
            "wrapper did not shut down cleanly: {status}"
        );
        assert_eq!(
            fs::read_to_string(directory.path().join("received")).unwrap(),
            expected
        );
        assert!(!directory.path().join("tunnellb-alive").exists());
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn unresponsive_child_is_killed_after_shutdown_deadline() {
    fs::create_dir_all("/tmp/codex").unwrap();
    let directory = tempfile::tempdir_in("/tmp/codex").unwrap();
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("trap '' TERM; printf started > \"$TUNNELLB_TEST_PROCESS_DIR/started\"; exec sleep 60")
        .env("TUNNELLB_TEST_PROCESS_DIR", directory.path());
    let mut process = Process::spawn(command).unwrap();
    wait_for_file(&directory.path().join("started")).await;

    let started = tokio::time::Instant::now();
    timeout(Duration::from_secs(8), process.stop(libc::SIGTERM))
        .await
        .unwrap()
        .unwrap();
    assert!(started.elapsed() >= SHUTDOWN_TIMEOUT);
    assert!(process.child.try_wait().unwrap().is_some());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn parent_death_kills_frp_even_without_drop_cleanup() {
    fs::create_dir_all("/tmp/codex").unwrap();
    let directory = tempfile::tempdir_in("/tmp/codex").unwrap();
    let mut command = fixture(directory.path());
    command.env("TUNNELLB_TEST_PARENT_DEATH", "1");
    let mut wrapper = command.spawn().unwrap();
    wait_for_file(&directory.path().join("child-pid")).await;
    let pid: i32 = fs::read_to_string(directory.path().join("child-pid"))
        .unwrap()
        .parse()
        .unwrap();

    wrapper.kill().await.unwrap();
    timeout(Duration::from_secs(5), async {
        loop {
            match fs::read_to_string(format!("/proc/{pid}/status")) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                Ok(status) if status.lines().any(|line| line.starts_with("State:\tZ")) => break,
                _ => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("FRP survived parent SIGKILL");
}
