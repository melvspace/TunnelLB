use super::*;
use crate::transport::FRP_VERSION;
use std::os::unix::fs::PermissionsExt;

#[test]
fn uninstall_retry_keeps_authoritative_owner_and_preserves_siblings() {
    let host = TestHost::new();
    let base = host.path("state");
    let owned = base.join("machine-uid");
    let binbase = host.path("opt");
    std::fs::create_dir_all(owned.join("publications")).unwrap();
    std::fs::create_dir_all(binbase.join(FRP_VERSION)).unwrap();
    std::fs::write(base.join("owner"), "machine-uid\n").unwrap();
    std::fs::write(owned.join("owner"), "machine-uid\n").unwrap();
    std::fs::write(binbase.join("owner"), "machine-uid\n").unwrap();
    std::fs::write(binbase.join(FRP_VERSION).join("frps"), "owned binary").unwrap();
    std::fs::write(base.join("unrelated"), "preserve me").unwrap();

    for path in [
        base.clone(),
        owned.clone(),
        owned.join("publications"),
        binbase.clone(),
        binbase.join(FRP_VERSION),
    ] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    for path in [
        base.join("owner"),
        owned.join("owner"),
        binbase.join("owner"),
        binbase.join(FRP_VERSION).join("frps"),
    ] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut request = request(Operation::Uninstall);

    for _ in 0..2 {
        host.success(uninstall_script(&request).unwrap());
    }

    assert!(!owned.exists());
    assert!(!binbase.join(FRP_VERSION).join("frps").exists());
    assert_eq!(
        std::fs::read_to_string(base.join("owner")).unwrap(),
        "machine-uid\n"
    );
    assert_eq!(
        std::fs::read_to_string(base.join("unrelated")).unwrap(),
        "preserve me"
    );
    request.machine_uid = "foreign-machine".into();
    host.failure(uninstall_script(&request).unwrap(), "owner");
}

#[test]
fn empty_host_remove_fences_delayed_apply_but_allows_fresh_credentials() {
    let host = TestHost::new();
    let old = request(Operation::Apply);
    host.success(remove_script(&old).unwrap());
    let marker = format!(
        "state/machine-uid/revocations/pub-0123-{}",
        old.generation.as_ref().unwrap()
    );
    assert!(host.path(&marker).is_file());
    host.enroll(&old);
    host.failure(apply_script(&old).unwrap(), "generation-revoked");
    let fresh = request(Operation::Apply);
    host.success(apply_script(&fresh).unwrap());
    assert!(host.path("active").exists());
}

#[test]
fn old_remove_and_apply_cannot_disturb_an_installed_replacement() {
    let host = TestHost::new();
    let old = request(Operation::Apply);
    host.enroll(&old);
    host.success(apply_script(&old).unwrap());
    host.success(remove_script(&old).unwrap());
    let fresh = request(Operation::Apply);
    host.success(apply_script(&fresh).unwrap());
    let payload = host.path("state/machine-uid/publications/pub-0123/frps.toml");
    let before = std::fs::read(&payload).unwrap();
    let commands_before = std::fs::read(host.path("commands")).unwrap();
    host.success(remove_script(&old).unwrap());
    host.failure(apply_script(&old).unwrap(), "generation-revoked");
    assert!(host.path("active").exists());
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
}

#[test]
fn failed_start_reserves_generation_until_matching_cleanup_finishes() {
    let host = TestHost::new();
    let old = request(Operation::Apply);
    host.enroll(&old);
    host.flag("fail-start");
    host.failure(apply_script(&old).unwrap(), "start");
    assert!(host.path("state/machine-uid/generations/pub-0123").exists());
    let fresh = request(Operation::Apply);
    host.failure(apply_script(&fresh).unwrap(), "generation-conflict");
    std::fs::remove_file(host.path("fail-start")).unwrap();
    host.success(apply_script(&old).unwrap());
    host.flag("fail-stop");
    host.failure(remove_script(&old).unwrap(), "stop");
    host.failure(apply_script(&old).unwrap(), "generation-revoked");
    host.failure(apply_script(&fresh).unwrap(), "generation-conflict");
    assert!(host.path("active").exists());
    std::fs::remove_file(host.path("fail-stop")).unwrap();
    host.flag("fail-payload-delete");
    host.failure(remove_script(&old).unwrap(), "command");
    assert!(
        !host
            .path("state/machine-uid/publications/pub-0123/owner")
            .exists()
    );
    assert!(host.path("state/machine-uid/generations/pub-0123").exists());
    host.success(remove_script(&old).unwrap());
    assert!(
        !host
            .path("state/machine-uid/publications/pub-0123")
            .exists()
    );
    assert!(!host.path("state/machine-uid/generations/pub-0123").exists());
    host.success(apply_script(&fresh).unwrap());
}

#[test]
fn uninstall_fences_empty_host_and_retries_after_inner_owner_is_deleted() {
    let request = request(Operation::Uninstall);
    let empty = TestHost::new();
    empty.success(uninstall_script(&request).unwrap());
    empty.success(uninstall_script(&request).unwrap());
    assert!(empty.path("state/uninstalled").exists());
    empty.failure(
        enroll_script(&request, None, AMD64_SHA256).unwrap(),
        "machine-revoked",
    );
    empty.failure(apply_script(&request).unwrap(), "machine-revoked");
    assert!(!empty.path("opt").exists());
    assert!(!empty.path("state/machine-uid").exists());

    let installed = TestHost::new();
    installed.enroll(&request);
    installed.success(apply_script(&request).unwrap());
    installed.flag("fail-owned-delete");
    installed.failure(uninstall_script(&request).unwrap(), "command");
    assert!(installed.path("state/uninstalled").exists());
    assert!(!installed.path("state/machine-uid/owner").exists());
    installed.failure(
        enroll_script(&request, None, AMD64_SHA256).unwrap(),
        "machine-revoked",
    );
    installed.failure(apply_script(&request).unwrap(), "machine-revoked");
    installed.success(uninstall_script(&request).unwrap());
    assert!(!installed.path("state/machine-uid").exists());
    assert!(!installed.path("active").exists());
}
