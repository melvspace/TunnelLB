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
    Failed(String),
}

#[cfg(test)]
mod tests;
