//! Accept bounded results only from the current Job's owned, successful worker.

use k8s_openapi::api::{
    batch::v1::Job,
    core::v1::{ContainerStateTerminated, Pod},
};
use kube::ResourceExt;
use serde_json::Value;

use super::{
    State,
    identity::{job_reference, same_owner},
};
use crate::provision;

pub(super) const WORKER: &str = "ssh-worker";
pub(super) const RESULT_LIMIT: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    Pending,
    Complete,
    Failed,
}

pub(super) fn phase(job: &Job) -> Phase {
    let Some(status) = &job.status else {
        return Phase::Pending;
    };

    let conditions = status.conditions.as_deref().unwrap_or_default();

    if conditions
        .iter()
        .any(|c| c.status == "True" && matches!(c.type_.as_str(), "Failed" | "FailureTarget"))
    {
        Phase::Failed
    } else if conditions
        .iter()
        .any(|c| c.status == "True" && c.type_ == "Complete")
    {
        Phase::Complete
    } else {
        // Failed Pod counts alone are not terminal: the Job may be retrying.
        Phase::Pending
    }
}

fn worker<'a>(job: &Job, pod: &'a Pod) -> Option<&'a ContainerStateTerminated> {
    let owner = job_reference(job).ok()?;

    if pod.uid().is_none_or(|uid| uid.is_empty())
        || pod.namespace() != job.namespace()
        || !pod.metadata.labels.as_ref().is_some_and(|labels| {
            ["batch.kubernetes.io/job-name", "job-name"]
                .iter()
                .any(|key| labels.get(*key) == Some(&owner.name))
        })
        || !pod
            .owner_references()
            .iter()
            .any(|actual| same_owner(actual, &owner))
    {
        return None;
    }

    let statuses = pod.status.as_ref()?.container_statuses.as_ref()?;
    let mut workers = statuses.iter().filter(|c| c.name == WORKER);
    let status = workers.next()?;

    if workers.next().is_some() {
        return None;
    }

    status.state.as_ref()?.terminated.as_ref()
}

pub(super) fn result(request: &provision::Request, job: &Job, pods: &[Pod]) -> State {
    match phase(job) {
        Phase::Pending => State::Pending,
        Phase::Failed => State::Failed(failure_message(job, pods)),
        Phase::Complete => {
            let successes: Vec<_> = pods
                .iter()
                .filter_map(|p| worker(job, p))
                .filter(|s| s.exit_code == 0)
                .collect();

            if successes.len() != 1 {
                return State::Failed(
                    "completed SSH Job has no unambiguous successful worker result".into(),
                );
            }

            let Some(message) = successes[0]
                .message
                .as_deref()
                .filter(|m| !m.is_empty() && m.len() <= RESULT_LIMIT)
            else {
                return State::Failed(
                    "completed SSH Job has a missing or oversized worker result".into(),
                );
            };

            // Reject error envelopes even if Outcome later gains serde defaults.
            if !serde_json::from_str::<Value>(message)
                .is_ok_and(|v| v.is_object() && v.get("error").is_none())
            {
                return State::Failed("completed SSH Job has an invalid worker result".into());
            }

            match serde_json::from_str::<provision::Outcome>(message) {
                Ok(outcome)
                    if !outcome.known_hosts.trim().is_empty()
                        && outcome
                            .fingerprint
                            .strip_prefix("SHA256:")
                            .is_some_and(|hash| !hash.is_empty())
                        && valid_architecture(request, &outcome.architecture) =>
                {
                    State::Complete(outcome)
                }

                _ => State::Failed("completed SSH Job has an invalid worker result".into()),
            }
        }
    }
}

fn valid_architecture(request: &provision::Request, architecture: &str) -> bool {
    if request.operation == provision::Operation::Enroll && request.expected_known_hosts.is_none() {
        // First contact only discovers a host key. The controller must persist
        // that pin before a separate, pinned enrollment may mutate the host.
        architecture.is_empty()
    } else {
        matches!(architecture, "amd64" | "arm64")
    }
}

fn failure_message(job: &Job, pods: &[Pod]) -> String {
    let reason = job
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| {
            cs.iter().find(|c| {
                c.status == "True" && matches!(c.type_.as_str(), "Failed" | "FailureTarget")
            })
        })
        .and_then(|c| c.reason.as_deref());
    let reason = match reason {
        Some("DeadlineExceeded") => "deadline exceeded",
        Some("BackoffLimitExceeded") => "retry limit exceeded",
        Some("PodFailurePolicy") => "worker Pod failed",
        _ => "execution failed",
    };

    let reported_error = pods
        .iter()
        .filter_map(|p| worker(job, p))
        .filter(|s| s.exit_code != 0)
        .filter_map(|s| s.message.as_deref())
        .filter(|m| m.len() <= RESULT_LIMIT)
        .any(|m| serde_json::from_str::<Value>(m).is_ok_and(|v| v.get("error").is_some()));

    // An error can contain arbitrary remote output, SSH key bytes, or fragments
    // of credentials. Fixed diagnostics are safer than substring redaction.
    if reported_error {
        format!("SSH Job {reason}; worker reported a provisioning error")
    } else {
        format!("SSH Job {reason}; no valid worker error result")
    }
}
