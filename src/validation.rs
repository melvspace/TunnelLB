//! Pure validation of administrator configuration and pod-backed publications.

mod backends;
mod primitives;
mod server;
mod service;

#[cfg(test)]
mod test_support;

use thiserror::Error;

pub use backends::validate_backends;
pub use server::validate_server;
pub use service::service_request;

/// Callers can downcast `anyhow::Error` to distinguish absence from unsafe input.
/// Only `BackendUnavailable` is a readiness/availability failure. All other
/// variants require revocation; never retain forwarding for an unverified Pod.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("InvalidServer: {0}")]
    InvalidServer(String),
    #[error("InvalidService: {0}")]
    InvalidService(String),
    #[error("UnsafeBackend: {0}")]
    UnsafeBackend(String),
    #[error("BackendUnavailable: {0}")]
    BackendUnavailable(String),
}

impl ValidationError {
    pub fn is_backend_unavailable(&self) -> bool {
        matches!(self, Self::BackendUnavailable(_))
    }
}
