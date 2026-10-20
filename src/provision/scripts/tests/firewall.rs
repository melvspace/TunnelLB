use super::*;

fn rule_path(host: &TestHost, request: &crate::provision::Request) -> std::path::PathBuf {
    let publication = request.publication.as_ref().unwrap();
    host.path(&format!(
        "ufw-rules/TunnelLB-{}",
        &digest(format!("{}:{}", request.server_uid, publication.id).as_bytes())[..32]
    ))
}

#[test]
fn uninstall_ignores_uncommitted_firewall_intent() {
    let host = TestHost::new();
    let request = request(Operation::Apply);
    host.enroll(&request);
    host.reserve(&request);
    host.success(apply_script(&request).unwrap());
    std::fs::write(
        host.path("state/server-uid/firewall/other-publication.pending.01234567"),
        "partial intent",
    )
    .unwrap();

    host.success(uninstall_script(&request).unwrap());
    assert!(!host.path("state/server-uid").exists());
    assert!(!rule_path(&host, &request).exists());
}

#[test]
fn publication_opens_control_and_exact_service_protocols_then_closes_them() {
    let host = TestHost::new();
    let request = request(Operation::Apply);
    host.enroll(&request);
    host.reserve(&request);
    host.success(apply_script(&request).unwrap());

    let profiles = std::fs::read_dir(host.path("ufw-rules"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        profiles.len(),
        1,
        "active UFW still blocks this publication"
    );
    let profile = std::fs::read_to_string(host.path(&format!(
        "ufw-apps/{}",
        profiles[0].file_name().to_str().unwrap()
    )))
    .unwrap();
    let ports = profile
        .lines()
        .find_map(|line| line.strip_prefix("ports="))
        .unwrap();
    let ports = ports.split('|').collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ports, ["22000/tcp", "443/tcp", "53/udp"].into());

    host.success(remove_script(&request).unwrap());
    assert_eq!(
        std::fs::read_dir(host.path("ufw-rules")).unwrap().count(),
        0
    );
    assert_eq!(std::fs::read_dir(host.path("ufw-apps")).unwrap().count(), 0);
}

#[test]
fn enrollment_inspects_firewall_without_opening_unallocated_ports() {
    let host = TestHost::new();
    let request = request(Operation::Enroll);
    host.enroll(&request);
    assert_eq!(
        std::fs::read_dir(host.path("ufw-rules")).unwrap().count(),
        0
    );
    assert_eq!(
        std::fs::read_to_string(host.path("firewall-commands")).unwrap(),
        "status\n"
    );
    host.flag("fail-firewall-inspection");
    host.failure(
        enroll_script(&request, None, AMD64_SHA256).unwrap(),
        "firewall-inspection",
    );
}

#[test]
fn unchanged_apply_repairs_missing_rules_without_restarting_frp() {
    let host = TestHost::new();
    let request = request(Operation::Apply);
    host.enroll(&request);
    host.reserve(&request);
    host.success(apply_script(&request).unwrap());
    let pid = std::fs::read(host.active(&request)).unwrap();
    let rule = rule_path(&host, &request);
    std::fs::remove_file(&rule).unwrap();

    host.success(apply_script(&request).unwrap());
    assert!(rule.exists());
    assert_eq!(std::fs::read(host.active(&request)).unwrap(), pid);
    host.success(apply_script(&request).unwrap());
    assert_eq!(
        std::fs::read_dir(host.path("ufw-rules")).unwrap().count(),
        1
    );
}

#[test]
fn failed_firewall_open_and_close_keep_claims_until_cleanup_succeeds() {
    let host = TestHost::new();
    let request = request(Operation::Apply);
    host.enroll(&request);
    host.reserve(&request);
    host.flag("fail-firewall-open");
    host.failure(apply_script(&request).unwrap(), "firewall-configuration");
    assert!(!host.active(&request).exists());
    assert!(host.path("state/server-uid/firewall/pub-0123").exists());

    std::fs::remove_file(host.path("fail-firewall-open")).unwrap();
    host.success(apply_script(&request).unwrap());
    host.flag("fail-firewall-close");
    host.failure(remove_script(&request).unwrap(), "firewall-cleanup");
    assert!(!host.active(&request).exists());
    assert!(rule_path(&host, &request).exists());
    assert!(host.path("state/claims/server-uid/pub-0123.claim").exists());
    host.failure(apply_script(&request).unwrap(), "generation-revoked");

    std::fs::remove_file(host.path("fail-firewall-close")).unwrap();
    host.success(remove_script(&request).unwrap());
    assert!(!rule_path(&host, &request).exists());
    assert!(!host.path("state/claims/server-uid/pub-0123.claim").exists());
    host.success(remove_script(&request).unwrap());
}

#[test]
fn inactive_ufw_keeps_persistent_rules_without_changing_firewall_state() {
    let host = TestHost::new();
    let request = request(Operation::Apply);
    host.flag("inactive-ufw");
    host.enroll(&request);
    host.reserve(&request);
    host.success(apply_script(&request).unwrap());
    assert!(rule_path(&host, &request).exists());
    host.success(remove_script(&request).unwrap());
    assert!(!rule_path(&host, &request).exists());
    let commands = std::fs::read_to_string(host.path("firewall-commands")).unwrap();
    assert!(!commands.lines().any(|line| {
        ["enable", "disable", "reset", "reload", "default"]
            .iter()
            .any(|command| line.contains(command))
    }));
}

#[test]
fn missing_ufw_is_allowed_only_when_no_managed_rules_need_reconciliation() {
    let host = TestHost::new();
    let request = request(Operation::Apply);
    host.flag("no-ufw");
    host.enroll(&request);
    host.reserve(&request);
    host.success(apply_script(&request).unwrap());
    assert!(!host.path("state/server-uid/firewall").exists());
    assert!(!host.path("firewall-commands").exists());

    std::fs::remove_file(host.path("no-ufw")).unwrap();
    host.success(apply_script(&request).unwrap());
    host.flag("no-ufw");
    host.failure(apply_script(&request).unwrap(), "firewall-unavailable");
    host.failure(remove_script(&request).unwrap(), "firewall-unavailable");
    assert!(host.path("state/claims/server-uid/pub-0123.claim").exists());
}

#[test]
fn stale_remove_cannot_close_replacement_rules() {
    let host = TestHost::new();
    let old = request(Operation::Apply);
    host.enroll(&old);
    host.reserve(&old);
    host.success(apply_script(&old).unwrap());
    host.success(remove_script(&old).unwrap());
    let fresh = request(Operation::Apply);
    host.reserve(&fresh);
    host.success(apply_script(&fresh).unwrap());

    host.success(remove_script(&old).unwrap());
    assert!(rule_path(&host, &fresh).exists());
    assert!(host.active(&fresh).exists());
    host.failure(apply_script(&old).unwrap(), "generation-revoked");
}

#[test]
fn uninstall_preserves_foreign_rules_and_other_servers() {
    let host = TestHost::new();
    let first = request(Operation::Apply);
    let mut second = request(Operation::Apply);
    second.server_uid = "another-server".into();
    let publication = second.publication.as_mut().unwrap();
    publication.server_uid.clone_from(&second.server_uid);
    publication.control_port = 22001;
    publication.service.ports[0].port = 8443;
    publication.service.ports[1].port = 1053;
    // The script fixture validates configuration separately from FRP; its
    // ownership, port reservations, firewall and process lifecycle are real.
    let foreign = "ufw allow 443/tcp comment 'administrator'\n";
    std::fs::write(host.path("ufw-rules/administrator"), foreign).unwrap();

    for request in [&first, &second] {
        host.enroll(request);
        host.reserve(request);
        host.success(apply_script(request).unwrap());
    }

    host.success(uninstall_script(&first).unwrap());
    assert!(!rule_path(&host, &first).exists());
    assert!(rule_path(&host, &second).exists());
    assert!(host.active(&second).exists());
    assert_eq!(
        std::fs::read_to_string(host.path("ufw-rules/administrator")).unwrap(),
        foreign
    );
    host.success(uninstall_script(&first).unwrap());
}

#[test]
fn cleanup_recovers_after_profile_unlink_but_before_intent_unlink() {
    let host = TestHost::new();
    let request = request(Operation::Apply);
    host.enroll(&request);
    host.reserve(&request);
    host.success(apply_script(&request).unwrap());
    host.flag("fail-firewall-profile-sync");
    host.failure(remove_script(&request).unwrap(), "command");
    assert!(host.path("state/server-uid/firewall/pub-0123").exists());
    assert!(host.path("state/claims/server-uid/pub-0123.claim").exists());
    assert_eq!(std::fs::read_dir(host.path("ufw-apps")).unwrap().count(), 0);

    std::fs::remove_file(host.path("fail-firewall-profile-sync")).unwrap();
    host.success(uninstall_script(&request).unwrap());
    assert!(!rule_path(&host, &request).exists());
    assert!(!host.path("state/server-uid").exists());
}

#[test]
fn changed_external_profile_blocks_cleanup_without_releasing_its_claim() {
    let host = TestHost::new();
    let request = request(Operation::Apply);
    host.enroll(&request);
    host.reserve(&request);
    host.success(apply_script(&request).unwrap());
    let rule = rule_path(&host, &request);
    let profile = host.path(&format!(
        "ufw-apps/{}",
        rule.file_name().unwrap().to_str().unwrap()
    ));
    let original = std::fs::read(&profile).unwrap();
    std::fs::write(&profile, "[External]\nports=1234/tcp\n").unwrap();

    host.failure(remove_script(&request).unwrap(), "firewall-configuration");
    assert!(rule.exists());
    assert!(host.path("state/claims/server-uid/pub-0123.claim").exists());
    std::fs::write(&profile, original).unwrap();
    host.success(remove_script(&request).unwrap());
    assert!(!rule.exists());
}
