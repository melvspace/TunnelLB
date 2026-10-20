use super::*;

fn registrations() -> Registrations {
    Registrations::from_config(
        r#"
            log.to = "console"
            log.level = "debug"
            log.disablePrintColor = true
            [[proxies]]
            name = "test-tcp"
            type = "tcp"
            [[proxies]]
            name = "dns-udp"
            type = "udp"
        "#,
    )
    .unwrap()
}

fn log(source: &str, level: char, message: &str) -> String {
    format!("2026-10-20 10:00:00.000 [{level}] [client/{source}:160] [run] {message}")
}

#[test]
fn readiness_requires_all_registrations_and_resets_on_reconnect() {
    let mut state = registrations();
    state.observe(&log(
        "service.go",
        'I',
        "login to server success, get run id [run]",
    ));
    assert!(!state.ready());

    for reset in [
        "2026-10-20 15:33:23.432 [D] [client/control.go:286] [472a83cde76a68fc] control message dispatcher exited".into(),
        log("service.go", 'I', "try to connect to server..."),
        log("control.go", 'W', "heartbeat timeout"),
        log("control.go", 'E', "pong message contains error: rejected"),
        log("service.go", 'W', "connect to server error: refused"),
    ] {
        // Literal v0.71.1 output anchors the parser to the bundled FRP format.
        state.observe("2026-10-20 15:33:23.386 [I] [client/control.go:174] [472a83cde76a68fc] [test-tcp] start proxy success");
        assert!(!state.ready());
        state.observe(&log("control.go", 'I', "[dns-udp] start proxy success"));
        assert!(state.ready());
        state.observe(&reset);
        assert!(!state.ready());
    }
}

#[test]
fn readiness_ignores_unknown_proxies_and_error_embedded_success() {
    let mut state = registrations();

    for line in [
        log("control.go", 'I', "[unknown] start proxy success"),
        log("service.go", 'I', "[test-tcp] start proxy success"),
        log(
            "control.go",
            'W',
            "[test-tcp] start error: [test-tcp] start proxy success",
        ),
        log(
            "control.go",
            'W',
            "server error: [I] [client/control.go:174] [test-tcp] start proxy success",
        ),
        "[test-tcp] start proxy success".into(),
        log(
            "control.go",
            'I',
            "[dns-udp] start proxy success trailing text",
        ),
    ] {
        state.observe(&line);
        assert!(state.registered.is_empty(), "{line}");
    }
}

#[test]
fn partial_registration_failure_preserves_successful_siblings() {
    let mut state = registrations();
    state.observe(&log("control.go", 'I', "[test-tcp] start proxy success"));
    state.observe(&log(
        "control.go",
        'W',
        "[dns-udp] start error: temporary failure",
    ));
    assert!(!state.ready());
    assert!(state.registered.contains("test-tcp"));
    state.observe(&log("control.go", 'I', "[dns-udp] start proxy success"));
    assert!(state.ready());

    state.observe(&log(
        "control.go",
        'W',
        "[test-tcp] start error: port in use",
    ));
    assert!(!state.ready());
    state.observe(&log("control.go", 'I', "[test-tcp] start proxy success"));
    assert!(state.ready());
}

#[test]
fn readiness_fails_closed_on_configuration_mismatch() {
    for config in [
        "",
        "[[proxies]]\nname='x'\ntype='tcp'",
        "log.to='console'\nlog.level='info'\nlog.disablePrintColor=true\n[[proxies]]\nname='x'\ntype='tcp'",
        "log.to='console'\nlog.level='debug'\nlog.disablePrintColor=true\nproxies=[]",
        "log.to='console'\nlog.level='debug'\nlog.disablePrintColor=true\n[[proxies]]\nname='x] start proxy success'\ntype='tcp'",
    ] {
        assert!(Registrations::from_config(config).is_err());
    }
}

#[test]
fn markers_are_removed_on_shutdown() {
    fs::create_dir_all("/tmp/codex").unwrap();
    let directory = tempfile::tempdir_in("/tmp/codex").unwrap();
    let path = directory.path().join("ready");
    let markers = HealthMarkers::new(&path).unwrap();
    markers.refresh(false).unwrap();
    assert!(ready(&path).is_err());
    assert!(ready(&markers.alive).is_ok());

    markers.refresh(true).unwrap();
    assert!(ready(&path).is_ok());

    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(60)))
        .unwrap();
    assert!(ready(&path).is_err(), "stale readiness must expire");

    drop(markers);
    assert!(!path.exists());
    assert!(!directory.path().join("tunnellb-alive").exists());
}
