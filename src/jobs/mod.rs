//! Reconcile immutable, content-addressed SSH Jobs without performing SSH here.

mod artifacts;
mod cleanup;
mod identity;
mod outcome;
mod runtime;

pub use cleanup::cleanup;
pub use runtime::run;

/// A verified Job's progress; failures contain only credential-safe diagnostics.
#[derive(Debug)]
pub enum State {
    Pending,
    Complete(crate::provision::Outcome),
    Failed(Failure),
}

/// Constructed only from fixed local messages and allowlisted worker codes.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct Failure {
    message: String,
    diagnostic: Option<crate::provision::Diagnostic>,
}

impl Failure {
    pub fn reason(&self) -> &'static str {
        self.diagnostic
            .map_or("SSHFailed", crate::provision::Diagnostic::reason)
    }
}

impl From<&'static str> for Failure {
    fn from(message: &'static str) -> Self {
        Self {
            message: message.into(),
            diagnostic: None,
        }
    }
}

#[cfg(test)]
mod tests;
