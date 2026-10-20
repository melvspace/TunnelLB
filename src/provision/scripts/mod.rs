//! Remote scripts share ownership checks but keep server and publication lifecycles separate.
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

mod firewall;
mod host;
mod publication;
mod reservation;
mod server;
#[cfg(test)]
mod tests;

pub(super) use publication::{apply_script, remove_script};
pub(super) use reservation::{parse_allocation, reserve_script};
pub(super) use server::{enroll_script, probe_script, uninstall_script};

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn upload(script: &mut String, target: &str, bytes: &[u8]) {
    // A fixed, underscored delimiter cannot occur in standard base64. The only
    // target values passed here are literal paths authored by these scripts.
    script.push_str(&format!(
        "base64 -d > {target} <<'TUNNELLB_BASE64_EOF'\n{}\nTUNNELLB_BASE64_EOF\n",
        STANDARD.encode(bytes)
    ));
}
