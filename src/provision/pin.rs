//! Parse one concrete host key and select a deterministic enrollment pin.
use std::net::Ipv4Addr;

use anyhow::{Context, Result, bail, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};

use sha2::{Digest, Sha256};

pub(super) struct Pin {
    pub(super) line: String,
    pub(super) fingerprint: String,
    pub(super) algorithm: String,
}

pub(super) fn host_label(address: Ipv4Addr, port: u16) -> String {
    if port == 22 {
        address.to_string()
    } else {
        format!("[{address}]:{port}")
    }
}

pub(super) fn parse_pin(value: &str, address: Ipv4Addr, port: u16) -> Result<Pin> {
    ensure!(value.len() <= 2048, "SSH host-key pin exceeds 2048 bytes");
    let lines: Vec<_> = value
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    ensure!(
        lines.len() == 1,
        "SSH host-key pin must contain exactly one host key"
    );
    let fields: Vec<_> = lines[0].split_whitespace().collect();
    ensure!(
        fields.len() == 3 && fields[0] == host_label(address, port),
        "SSH host-key pin must name exactly the requested address and port without aliases or markers"
    );
    let algorithm = match fields[1] {
        "ssh-ed25519" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            fields[1]
        }

        "ssh-rsa" => "rsa-sha2-512,rsa-sha2-256",
        _ => bail!("unsupported SSH host-key algorithm"),
    };

    let decoded = STANDARD
        .decode(fields[2])
        .context("SSH host-key pin has invalid base64")?;
    let mut cursor = decoded.as_slice();
    ensure!(
        ssh_string(&mut cursor)? == fields[1].as_bytes(),
        "SSH host-key type does not match its key blob"
    );

    match fields[1] {
        "ssh-ed25519" => ensure!(
            ssh_string(&mut cursor)?.len() == 32,
            "invalid Ed25519 host key"
        ),
        "ssh-rsa" => {
            ensure!(!ssh_string(&mut cursor)?.is_empty(), "invalid RSA exponent");
            let modulus = ssh_string(&mut cursor)?;
            let significant = modulus
                .iter()
                .position(|byte| *byte != 0)
                .map(|offset| &modulus[offset..])
                .context("invalid RSA modulus")?;
            let bits = significant.len() * 8 - significant[0].leading_zeros() as usize;
            ensure!(
                (2048..=8192).contains(&bits),
                "RSA host key must contain 2048 to 8192 bits"
            );
        }

        kind => {
            ensure!(
                ssh_string(&mut cursor)? == kind.strip_prefix("ecdsa-sha2-").unwrap().as_bytes(),
                "ECDSA host key curve mismatch"
            );
            let point = ssh_string(&mut cursor)?;
            let expected = match kind {
                "ecdsa-sha2-nistp256" => 65,
                "ecdsa-sha2-nistp384" => 97,
                _ => 133,
            };

            ensure!(
                point.len() == expected && point[0] == 4,
                "invalid ECDSA host key point"
            );
        }
    }

    ensure!(cursor.is_empty(), "SSH host key has trailing data");
    let fingerprint = format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(&decoded))
    );

    Ok(Pin {
        line: format!("{} {} {}\n", fields[0], fields[1], fields[2]),
        fingerprint,
        algorithm: algorithm.into(),
    })
}

fn ssh_string<'a>(remaining: &mut &'a [u8]) -> Result<&'a [u8]> {
    ensure!(remaining.len() >= 4, "truncated SSH host key");
    let length = u32::from_be_bytes(remaining[..4].try_into().unwrap()) as usize;
    *remaining = &remaining[4..];
    ensure!(length <= remaining.len(), "truncated SSH host key field");
    let field = &remaining[..length];
    *remaining = &remaining[length..];

    Ok(field)
}

pub(super) fn select_scan_pin(output: &str, address: Ipv4Addr, port: u16) -> Result<Pin> {
    // Prefer one concrete key. Subsequent connections cannot fall back to a
    // newly scanned alternative if this key changes.
    for algorithm in [
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "ssh-rsa",
    ] {
        let matching: Vec<_> = output
            .lines()
            .filter(|line| line.split_whitespace().nth(1) == Some(algorithm))
            .collect();

        if let Some(line) = matching.first() {
            ensure!(
                matching.iter().all(|candidate| candidate == line),
                "SSH key scan returned conflicting keys"
            );

            return parse_pin(line, address, port);
        }
    }

    bail!("SSH key scan returned no supported host key; check the SSH endpoint")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision::test_support::host_key;

    #[test]
    fn pins_are_one_exact_host_key_with_verified_blob_shape() {
        let address = "203.0.113.7".parse().unwrap();
        let value = host_key(address, 2222, 1);
        let pin = parse_pin(&value, address, 2222).unwrap();
        assert_eq!(pin.line, value);
        assert!(pin.fingerprint.starts_with("SHA256:"));
        assert_ne!(
            pin.fingerprint,
            parse_pin(&host_key(address, 2222, 2), address, 2222)
                .unwrap()
                .fingerprint
        );

        for bad in [
            value.replace("[203.0.113.7]:2222", "*"),
            value.replace("[203.0.113.7]:2222", "[203.0.113.8]:2222"),
            format!("{value}{value}"),
            format!("@cert-authority {value}"),
            value.replace("ssh-ed25519 ", "ssh-rsa "),
            "203.0.113.7 ssh-ed25519 !!!!".into(),
        ] {
            assert!(parse_pin(&bad, address, 2222).is_err());
        }

        assert!(parse_pin(&value, address, 22).is_err());
    }
}
