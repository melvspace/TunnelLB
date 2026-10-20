use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use k8s_openapi::{ByteString, api::core::v1::Secret};
use kube::{Api, api::PostParams};
use serde::{Deserialize, Serialize};

use super::{
    MACHINE_UID_LABEL, MAX_ATTEMPTS, Store, delete_params, delete_result, has_status,
    machine_labels, machine_state_name, owned_labels, publication_labels, required_label,
    validate_id,
};
use crate::{
    api::{MACHINE_LABEL, PUBLICATION_LABEL, Publication, SERVICE_UID_LABEL},
    transport::{self, Credentials},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPin {
    pub known_hosts: String,
    pub fingerprint: String,
    pub address: String,
    pub ssh_port: u16,
}

impl Store {
    fn secrets(&self) -> Api<Secret> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    pub async fn pin(&self, machine_uid: &str) -> Result<Option<HostPin>> {
        let labels = machine_labels("host-pin", machine_uid)?;
        let name = machine_state_name("host", machine_uid);
        self.secrets()
            .get_opt(&name)
            .await?
            .map(|secret| {
                self.check_owned(&secret.metadata, &name, &labels)?;
                read_pin(&secret)
            })
            .transpose()
    }

    /// First enrollment wins. A changed key or endpoint requires explicit
    /// removal of the previous pin; no retry may silently replace it.
    pub async fn save_pin(&self, machine_uid: &str, pin: &HostPin) -> Result<()> {
        validate_pin(pin)?;
        let labels = machine_labels("host-pin", machine_uid)?;
        let name = machine_state_name("host", machine_uid);
        let encoded = serde_json::to_vec(pin).context("serializing host pin")?;
        let api = self.secrets();

        for _ in 0..MAX_ATTEMPTS {
            if let Some(secret) = api.get_opt(&name).await? {
                self.check_owned(&secret.metadata, &name, &labels)?;
                let existing = read_pin(&secret)?;

                return ensure_same_pin(&existing, pin);
            }

            let secret = Secret {
                metadata: self.metadata(&name, labels.clone()),
                immutable: Some(true),
                type_: Some("Opaque".into()),
                data: Some(BTreeMap::from([(
                    "pin.json".into(),
                    ByteString(encoded.clone()),
                )])),
                ..Default::default()
            };
            match api.create(&PostParams::default(), &secret).await {
                Ok(persisted) => {
                    self.check_owned(&persisted.metadata, &name, &labels)?;

                    return ensure_same_pin(&read_pin(&persisted)?, pin);
                }

                Err(error) if has_status(&error, 409) => continue,
                Err(error) => return Err(error.into()),
            }
        }

        bail!("host pin remained contended after {MAX_ATTEMPTS} attempts")
    }

    pub async fn delete_pin(&self, machine_uid: &str) -> Result<()> {
        let labels = machine_labels("host-pin", machine_uid)?;
        let name = machine_state_name("host", machine_uid);
        let api = self.secrets();

        if let Some(secret) = api.get_opt(&name).await? {
            self.check_owned(&secret.metadata, &name, &labels)?;
            delete_result(api.delete(&name, &delete_params(&secret.metadata)?).await)?;
        }

        Ok(())
    }

    /// Return the persisted winner, including when another instance wins a
    /// create race. Never regenerate malformed or foreign credential state.
    pub async fn credentials(&self, publication: &Publication) -> Result<Credentials> {
        let labels = publication_labels("credentials", publication)?;
        let name = format!("credentials-{}", publication.id);
        let api = self.secrets();

        for _ in 0..MAX_ATTEMPTS {
            if let Some(secret) = api.get_opt(&name).await? {
                self.check_owned(&secret.metadata, &name, &labels)?;

                return read_credentials(&secret);
            }

            let generated = transport::credentials(publication)?;
            let secret = Secret {
                metadata: self.metadata(&name, labels.clone()),
                immutable: Some(true),
                type_: Some("Opaque".into()),
                data: Some(BTreeMap::from([
                    ("token".into(), ByteString(generated.token.into_bytes())),
                    (
                        "tls.crt".into(),
                        ByteString(generated.certificate_pem.into_bytes()),
                    ),
                    (
                        "tls.key".into(),
                        ByteString(generated.private_key_pem.into_bytes()),
                    ),
                ])),
                ..Default::default()
            };
            match api.create(&PostParams::default(), &secret).await {
                Ok(persisted) => {
                    self.check_owned(&persisted.metadata, &name, &labels)?;

                    return read_credentials(&persisted);
                }

                Err(error) if has_status(&error, 409) => continue,
                Err(error) => return Err(error.into()),
            }
        }

        bail!("credentials remained contended after {MAX_ATTEMPTS} attempts")
    }

    pub async fn delete_credentials(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        let name = format!("credentials-{id}");
        let api = self.secrets();

        if let Some(secret) = api.get_opt(&name).await? {
            let mut labels = owned_labels("credentials");
            labels.insert(PUBLICATION_LABEL.into(), id.into());

            for key in [MACHINE_LABEL, MACHINE_UID_LABEL, SERVICE_UID_LABEL] {
                labels.insert(key.into(), required_label(&secret.metadata, key)?.into());
            }

            self.check_owned(&secret.metadata, &name, &labels)?;
            delete_result(api.delete(&name, &delete_params(&secret.metadata)?).await)?;
        }

        Ok(())
    }
}

fn secret_value<'a>(secret: &'a Secret, key: &str) -> Result<&'a str> {
    let bytes = secret
        .data
        .as_ref()
        .and_then(|data| data.get(key))
        .with_context(|| format!("state Secret is missing {key}"))?;
    let value = std::str::from_utf8(&bytes.0)
        .with_context(|| format!("state Secret field {key} is not UTF-8"))?;
    ensure!(!value.is_empty(), "state Secret field {key} is empty");

    Ok(value)
}

fn read_pin(secret: &Secret) -> Result<HostPin> {
    ensure!(
        secret.immutable == Some(true),
        "host pin Secret is not immutable"
    );
    let pin =
        serde_json::from_str(secret_value(secret, "pin.json")?).context("decoding SSH host pin")?;
    validate_pin(&pin)?;

    Ok(pin)
}

fn validate_pin(pin: &HostPin) -> Result<()> {
    ensure!(
        !pin.known_hosts.is_empty()
            && !pin.fingerprint.is_empty()
            && !pin.address.is_empty()
            && pin.ssh_port != 0,
        "host pin is incomplete"
    );

    Ok(())
}

fn ensure_same_pin(existing: &HostPin, proposed: &HostPin) -> Result<()> {
    ensure!(
        existing.known_hosts == proposed.known_hosts
            && existing.fingerprint == proposed.fingerprint
            && existing.address == proposed.address
            && existing.ssh_port == proposed.ssh_port,
        "SSH host pin changed; explicit re-enrollment is required"
    );

    Ok(())
}

fn read_credentials(secret: &Secret) -> Result<Credentials> {
    ensure!(
        secret.immutable == Some(true),
        "credentials Secret is not immutable"
    );

    Ok(Credentials {
        token: secret_value(secret, "token")?.into(),
        certificate_pem: secret_value(secret, "tls.crt")?.into(),
        private_key_pem: secret_value(secret, "tls.key")?.into(),
    })
}
