use super::*;

#[test]
fn legacy_markers_fail_before_creating_shared_state() {
    let request = request(Operation::Uninstall);

    for marker in ["state/owner", "opt/owner"] {
        let host = TestHost::new();
        let path = host.path(marker);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "server-uid\n").unwrap();

        for script in [
            enroll_script(&request, None, AMD64_SHA256).unwrap(),
            reserve_script(&request).unwrap(),
            apply_script(&request).unwrap(),
            remove_script(&request).unwrap(),
            uninstall_script(&request).unwrap(),
        ] {
            host.failure(script, "legacy-layout");
        }

        assert_eq!(std::fs::read_to_string(path).unwrap(), "server-uid\n");
        assert!(!host.path("state/schema").exists());
        assert!(!host.path("lock").exists());
    }
}

#[test]
fn empty_host_remove_fences_delayed_apply_but_allows_fresh_credentials() {
    let host = TestHost::new();
    let old = request(Operation::Apply);
    host.success(remove_script(&old).unwrap());
    let marker = format!(
        "state/server-uid/revocations/pub-0123-{}",
        old.generation.as_ref().unwrap()
    );
    assert!(host.path(&marker).is_file());
    host.enroll(&old);
    host.failure(apply_script(&old).unwrap(), "generation-revoked");
    let fresh = request(Operation::Apply);
    host.reserve(&fresh);
    host.success(apply_script(&fresh).unwrap());
    assert!(host.active(&fresh).exists());
}

#[test]
fn old_remove_and_apply_cannot_disturb_an_installed_replacement() {
    let host = TestHost::new();
    let old = request(Operation::Apply);
    host.enroll(&old);
    host.reserve(&old);
    host.success(apply_script(&old).unwrap());
    host.success(remove_script(&old).unwrap());
    let fresh = request(Operation::Apply);
    host.reserve(&fresh);
    host.success(apply_script(&fresh).unwrap());
    let payload = host.path("state/server-uid/publications/pub-0123/frps.toml");
    let before = std::fs::read(&payload).unwrap();
    let commands_before = std::fs::read(host.path("commands")).unwrap();
    host.success(remove_script(&old).unwrap());
    host.failure(apply_script(&old).unwrap(), "generation-revoked");
    assert!(host.active(&fresh).exists());
    assert_eq!(std::fs::read(&payload).unwrap(), before);
    assert_eq!(
        std::fs::read(host.path("commands")).unwrap(),
        commands_before
    );
    let mut changed_config = fresh;
    changed_config
        .server_config
        .as_mut()
        .unwrap()
        .push_str("\n# reordered request\n");
    host.failure(
        apply_script(&changed_config).unwrap(),
        "generation-conflict",
    );
    assert_eq!(std::fs::read(payload).unwrap(), before);
    std::fs::remove_file(host.path("state/server-uid/generations/pub-0123")).unwrap();
    host.failure(apply_script(&changed_config).unwrap(), "generation-state");
}

#[test]
fn interrupted_retirement_is_synced_again_before_any_claim_release() {
    let host = TestHost::new();
    let request = request(Operation::Uninstall);
    host.enroll(&request);
    host.reserve(&request);
    host.success(apply_script(&request).unwrap());
    host.flag("fail-retired-sync");

    for _ in 0..2 {
        host.failure(uninstall_script(&request).unwrap(), "command");
        assert!(host.active(&request).exists());
        assert!(host.path("state/claims/server-uid/pub-0123.claim").exists());
    }

    host.failure(remove_script(&request).unwrap(), "command");
    assert!(host.active(&request).exists());
    std::fs::remove_file(host.path("fail-retired-sync")).unwrap();
    host.success(uninstall_script(&request).unwrap());
    assert!(!host.active(&request).exists());
}

#[test]
fn cleanup_retries_sync_parents_even_after_entries_have_disappeared() {
    for parent in [
        "state/server-uid/publications",
        "state/server-uid/firewall",
        "state/server-uid/generations",
        "state/claims/server-uid",
    ] {
        let host = TestHost::new();
        let request = request(Operation::Remove);
        host.enroll(&request);
        host.reserve(&request);
        host.success(apply_script(&request).unwrap());
        std::fs::write(
            host.path("fail-directory-sync"),
            host.path(parent).to_str().unwrap(),
        )
        .unwrap();

        for _ in 0..2 {
            host.failure(remove_script(&request).unwrap(), "command");
        }

        if parent == "state/claims/server-uid" {
            host.failure(uninstall_script(&request).unwrap(), "command");
        } else {
            assert!(host.path("state/claims/server-uid/pub-0123.claim").exists());
        }

        std::fs::remove_file(host.path("fail-directory-sync")).unwrap();
        host.success(uninstall_script(&request).unwrap());
    }
}

#[test]
fn failed_start_reserves_generation_until_matching_cleanup_finishes() {
    let host = TestHost::new();
    let old = request(Operation::Apply);
    host.enroll(&old);
    host.reserve(&old);
    host.flag("fail-start");
    host.failure(apply_script(&old).unwrap(), "start");
    assert!(host.path("state/server-uid/generations/pub-0123").exists());
    let fresh = request(Operation::Apply);
    host.failure(apply_script(&fresh).unwrap(), "reservation-conflict");
    std::fs::remove_file(host.path("fail-start")).unwrap();
    host.success(apply_script(&old).unwrap());
    host.flag("fail-stop");
    host.failure(remove_script(&old).unwrap(), "stop");
    host.failure(apply_script(&old).unwrap(), "generation-revoked");
    host.failure(apply_script(&fresh).unwrap(), "reservation-conflict");
    assert!(host.active(&old).exists());
    std::fs::remove_file(host.path("fail-stop")).unwrap();
    host.flag("fail-payload-delete");
    host.failure(remove_script(&old).unwrap(), "command");
    assert!(
        !host
            .path("state/server-uid/publications/pub-0123/owner")
            .exists()
    );
    assert!(host.path("state/server-uid/generations/pub-0123").exists());
    host.flag("fail-generation-delete");
    host.failure(remove_script(&old).unwrap(), "command");
    assert!(host.path("state/claims/server-uid/pub-0123.claim").exists());
    host.success(remove_script(&old).unwrap());
    assert!(!host.path("state/server-uid/publications/pub-0123").exists());
    assert!(!host.path("state/server-uid/generations/pub-0123").exists());
    host.reserve(&fresh);
    host.success(apply_script(&fresh).unwrap());
}

#[test]
fn uninstall_fences_empty_host_and_retries_after_inner_owner_is_deleted() {
    let request = request(Operation::Uninstall);
    let empty = TestHost::new();
    empty.success(uninstall_script(&request).unwrap());
    empty.success(uninstall_script(&request).unwrap());
    assert!(empty.path("state/retired/server-uid").exists());
    empty.failure(
        enroll_script(&request, None, AMD64_SHA256).unwrap(),
        "server-revoked",
    );
    empty.failure(apply_script(&request).unwrap(), "server-revoked");
    assert!(!empty.path("opt").exists());
    assert!(!empty.path("state/server-uid").exists());

    let installed = TestHost::new();
    installed.enroll(&request);
    installed.reserve(&request);
    installed.success(apply_script(&request).unwrap());
    installed.flag("fail-owned-delete");
    installed.failure(uninstall_script(&request).unwrap(), "command");
    assert!(installed.path("state/retired/server-uid").exists());
    assert!(!installed.path("state/server-uid/owner").exists());
    installed.failure(
        enroll_script(&request, None, AMD64_SHA256).unwrap(),
        "server-revoked",
    );
    installed.failure(apply_script(&request).unwrap(), "server-revoked");
    installed.success(uninstall_script(&request).unwrap());
    assert!(!installed.path("state/server-uid").exists());
    assert!(!installed.active(&request).exists());
}
