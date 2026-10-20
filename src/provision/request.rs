//! Validate ownership, SSH targets, and exact publication credentials before I/O.
use anyhow::{Context, Result, ensure};

use super::{Operation, Request, pin::parse_pin};
use crate::transport::{self, Credentials};

pub(super) const FIELD_LIMIT: usize = 256 * 1024;

fn validate_component(value: &str, name: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 63
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
        "{name} must contain 1-63 ASCII letters, digits, hyphens or underscores"
    );

    Ok(())
}

pub(super) fn validate_request(request: &Request) -> Result<()> {
    validate_component(&request.machine_uid, "Machine UID")?;
    ensure!(
        !matches!(
            request.machine_uid.as_str(),
            "claims" | "retired" | "schema" | "owner" | "uninstalled"
        ),
        "Machine UID conflicts with a reserved host state directory"
    );
    ensure!(request.ssh_port != 0, "SSH port must be nonzero");
    ensure!(
        !request.address.is_unspecified()
            && !request.address.is_multicast()
            && !request.address.is_broadcast(),
        "SSH address must be a unicast IPv4 address"
    );
    let user = &request.ssh_user;
    ensure!(
        !user.is_empty()
            && user.len() <= 32
            && (user.as_bytes()[0].is_ascii_alphabetic() || user.as_bytes()[0] == b'_')
            && user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
        "SSH user must be a safe local account name of at most 32 characters"
    );
    ensure!(
        request.operation == Operation::Enroll || request.expected_known_hosts.is_some(),
        "only initial enrollment can omit the SSH host-key pin; restore operator state or explicitly re-enroll"
    );

    if let Some(pin) = &request.expected_known_hosts {
        parse_pin(pin, request.address, request.ssh_port)?;
    }

    if matches!(
        request.operation,
        Operation::Reserve | Operation::Apply | Operation::Remove
    ) {
        let publication = request
            .publication
            .as_ref()
            .context("publication is required for reserve/apply/remove")?;
        validate_component(&publication.id, "publication ID")?;
        ensure!(
            publication.machine_uid == request.machine_uid,
            "publication belongs to another Machine UID"
        );
        let generation = request
            .generation
            .as_deref()
            .context("credential generation is required for reserve/apply/remove")?;
        ensure!(
            generation.len() == 64
                && generation
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "credential generation must be 64 lowercase hexadecimal characters"
        );

        // Remove deliberately does not validate the old Service's current ports,
        // backend, address, or credentials. Only its ownership identity matters.
        if matches!(request.operation, Operation::Reserve | Operation::Apply) {
            ensure!(
                publication.machine_address == request.address,
                "publication address does not match the SSH target"
            );
            ensure!(
                publication
                    .service
                    .ports
                    .iter()
                    .all(|p| p.port != request.ssh_port),
                "publication cannot occupy the reserved SSH port"
            );
            ensure!(
                !publication.service.ports.is_empty()
                    && publication.service.ports.iter().all(|p| p.port != 0),
                "publication requires nonzero public ports"
            );
        }

        if request.operation == Operation::Reserve {
            let reservation = request
                .reservation
                .as_ref()
                .context("reservation is required")?;
            ensure!(
                reservation.control_port_range.start != 0
                    && reservation.control_port_range.start <= reservation.control_port_range.end
                    && reservation.excluded_ports.iter().all(|port| *port != 0),
                "reservation requires a nonzero ordered control range and nonzero exclusions"
            );
        }

        if request.operation == Operation::Apply {
            ensure!(
                publication.control_port != request.ssh_port
                    && publication
                        .service
                        .ports
                        .iter()
                        .all(|p| p.port != publication.control_port),
                "control port cannot overlap SSH or any numeric public port"
            );
            let config = required_field(&request.server_config, "server configuration")?;
            let cert = required_field(&request.server_certificate, "server certificate")?;
            let key = required_field(&request.server_private_key, "server private key")?;
            ensure!(
                generation == transport::credential_generation(cert),
                "credential generation does not match the server certificate"
            );
            // Compare semantic TOML with our own strict generator. This forbids
            // includes, templates, extra listeners and executable plugins even
            // if a malformed request reaches the worker.
            let actual: toml::Value = toml::from_str(config)
                .map_err(|_| anyhow::anyhow!("server configuration is invalid TOML"))?;
            let token = actual
                .get("auth")
                .and_then(|a| a.get("token"))
                .and_then(toml::Value::as_str)
                .context("server configuration requires a publication token")?;
            let credentials = Credentials {
                token: token.to_owned(),
                certificate_pem: cert.to_owned(),
                private_key_pem: key.to_owned(),
            };

            let generated = transport::server_config(publication, &credentials)?;
            let expected: toml::Value = toml::from_str(&generated)?;
            ensure!(
                actual == expected,
                "server configuration differs from the owned publication configuration"
            );
            ensure!(
                !config.contains("{{"),
                "server configuration must not contain FRP template directives"
            );
        }
    }

    Ok(())
}

pub(super) fn required_field<'a>(field: &'a Option<String>, label: &str) -> Result<&'a str> {
    let value = field
        .as_deref()
        .with_context(|| format!("{label} is required"))?;
    ensure!(
        !value.is_empty() && value.len() <= FIELD_LIMIT,
        "{label} is empty or exceeds 256 KiB"
    );

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision::{
        Outcome,
        test_support::{host_key, request},
    };

    #[test]
    fn request_and_outcome_wire_contract() {
        let request = request(Operation::Apply);
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["operation"], "apply");
        assert_eq!(value["address"], "203.0.113.7");
        assert!(value["publication"].is_object());
        assert!(value["serverPrivateKey"].is_string());
        let outcome = Outcome {
            known_hosts: request.expected_known_hosts.unwrap(),
            fingerprint: "SHA256:test".into(),
            architecture: "amd64".into(),
            allocation: None,
        };

        let serialized = serde_json::to_string(&outcome).unwrap();
        assert!(serialized.len() < 4096);
        assert_eq!(
            serde_json::from_str::<Outcome>(&serialized).unwrap(),
            outcome
        );
        assert!(
            serde_json::from_str::<Outcome>(r#"{"knownHosts":"x","fingerprint":"y"}"#).is_err()
        );
        assert!(
            serde_json::from_str::<Outcome>(
                r#"{"knownHosts":"x","fingerprint":"y","architecture":"amd64","error":"x"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn reject_injections_before_any_process() {
        for value in [
            "../other",
            "x\ny",
            "x;touch /tmp/pwn",
            "$(id)",
            "x'",
            "x%name",
            "",
        ] {
            let mut request = request(Operation::Apply);
            request.machine_uid = value.into();
            assert!(validate_request(&request).is_err());
        }

        for user in ["-oProxyCommand=id", "root@other", "a\nb", "a;id", "root "] {
            let mut request = request(Operation::Enroll);
            request.ssh_user = user.into();
            assert!(validate_request(&request).is_err());
        }
    }

    #[test]
    fn only_enrollment_can_tofu_and_remove_ignores_stale_service_validation() {
        let mut request = request(Operation::Enroll);
        request.expected_known_hosts = None;
        validate_request(&request).unwrap();

        for operation in [
            Operation::Reserve,
            Operation::Apply,
            Operation::Remove,
            Operation::Uninstall,
        ] {
            request.operation = operation;
            assert!(validate_request(&request).is_err());
        }

        request.operation = Operation::Remove;
        request.expected_known_hosts = Some(host_key(request.address, request.ssh_port, 1));
        request.publication.as_mut().unwrap().service.ports.clear();
        request.publication.as_mut().unwrap().control_port = 0;
        request.server_config = None;
        request.server_certificate = None;
        request.server_private_key = None;
        validate_request(&request).unwrap();
        request.publication.as_mut().unwrap().machine_uid = "other".into();
        assert!(validate_request(&request).is_err());
    }

    #[test]
    fn config_must_match_owned_publication_without_extra_features() {
        let mut request = request(Operation::Apply);
        validate_request(&request).unwrap();
        let mut config: toml::Value =
            toml::from_str(request.server_config.as_ref().unwrap()).unwrap();
        config.as_table_mut().unwrap().insert(
            "includes".into(),
            toml::Value::Array(vec!["/tmp/other.toml".into()]),
        );
        request.server_config = Some(toml::to_string(&config).unwrap());
        assert!(validate_request(&request).is_err());
        request.server_config = Some("auth.token = 'SECRET'\nmalformed = [".into());
        let error = validate_request(&request).unwrap_err().to_string();
        assert!(!error.contains("SECRET"));
    }

    #[test]
    fn leading_underscore_account_matches_machine_validation() {
        let mut request = request(Operation::Enroll);
        request.ssh_user = "_worker".into();
        validate_request(&request).unwrap();
    }

    #[test]
    fn reserve_needs_identity_and_numeric_ports_but_no_payload() {
        let mut valid = request(Operation::Reserve);
        valid.server_config = None;
        valid.server_certificate = None;
        valid.server_private_key = None;
        valid.publication.as_mut().unwrap().control_port = 0;
        validate_request(&valid).unwrap();
        let mut invalid = valid.clone();
        invalid.reservation = None;
        assert!(validate_request(&invalid).is_err());
        invalid = valid.clone();
        invalid.publication.as_mut().unwrap().service.ports.clear();
        assert!(validate_request(&invalid).is_err());

        for port in [0, valid.ssh_port] {
            invalid = valid.clone();
            invalid.publication.as_mut().unwrap().service.ports[0].port = port;
            assert!(validate_request(&invalid).is_err());
        }

        for range in [
            crate::api::PortRange { start: 0, end: 10 },
            crate::api::PortRange { start: 11, end: 10 },
        ] {
            invalid = valid.clone();
            invalid.reservation.as_mut().unwrap().control_port_range = range;
            assert!(validate_request(&invalid).is_err());
        }

        invalid = valid;
        invalid.reservation.as_mut().unwrap().excluded_ports.push(0);
        assert!(validate_request(&invalid).is_err());

        for owner in ["schema", "claims", "retired", "owner", "uninstalled"] {
            let mut invalid = request(Operation::Enroll);
            invalid.machine_uid = owner.into();
            assert!(validate_request(&invalid).is_err());
        }
    }

    #[test]
    fn missing_malformed_or_mismatched_generation_is_rejected_before_execution() {
        let valid = request(Operation::Apply);

        for generation in [
            None,
            Some("".into()),
            Some("A".repeat(64)),
            Some("a".repeat(63)),
            Some("g".repeat(64)),
            Some("../other".into()),
        ] {
            for operation in [Operation::Reserve, Operation::Apply, Operation::Remove] {
                let mut candidate = valid.clone();
                candidate.operation = operation;
                candidate.generation = generation.clone();
                assert!(validate_request(&candidate).is_err());
            }
        }

        let mut candidate = valid.clone();
        candidate.generation = Some("0".repeat(64));
        assert!(validate_request(&candidate).is_err());
        candidate = valid;
        candidate.server_certificate.as_mut().unwrap().push('\n');
        assert!(validate_request(&candidate).is_err());
        let wire = serde_json::to_value(request(Operation::Enroll)).unwrap();
        let mut absent = wire.clone();
        absent.as_object_mut().unwrap().remove("generation");
        assert!(
            serde_json::from_value::<Request>(absent)
                .unwrap()
                .generation
                .is_none()
        );
        let mut null = wire;
        null["generation"] = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<Request>(null)
                .unwrap()
                .generation
                .is_none()
        );
    }
}
