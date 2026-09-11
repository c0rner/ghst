pub mod store;

use crate::credential::{AccessToken, TokenExpiry};
use std::fmt;

/// Lifecycle state of a foreground invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunState {
    Pending,
    Running,
    CleanupPending,
}

/// Pure errors produced by invalid lifecycle state transitions.
#[derive(Debug, PartialEq, Eq)]
pub enum RunTransitionError {
    PendingOwnership,
    ReleasedOwnership,
    AbandonedRun,
    CleanupDeletion,
}

impl fmt::Display for RunTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PendingOwnership => write!(f, "pending run ownership did not match"),
            Self::ReleasedOwnership => write!(f, "released run ownership did not match"),
            Self::AbandonedRun => {
                write!(f, "abandoned run changed while checking liveness")
            }
            Self::CleanupDeletion => write!(f, "cleanup deletion ownership did not match"),
        }
    }
}

impl std::error::Error for RunTransitionError {}

/// Durable recovery record for a foreground command invocation.
#[derive(PartialEq, Eq)]
pub struct RunRecord {
    pub run_id: String,
    pub state: RunState,
    pub wrapper_pid: u32,
    pub child_pid: Option<u32>,
    pub command: String,
    pub profile: String,
    pub source_profile: String,
    pub source_authority_fingerprint: String,
    pub github_user: String,
    pub repo_scope: String,
    pub expires_at: TokenExpiry,
    pub access_token: AccessToken,
}

impl RunRecord {
    /// Validates and records child process spawn for a pending run.
    pub fn activate(
        &mut self,
        run_id: &str,
        wrapper_pid: u32,
        child_pid: u32,
    ) -> Result<(), RunTransitionError> {
        if self.run_id != run_id
            || self.wrapper_pid != wrapper_pid
            || self.child_pid.is_some()
            || self.state != RunState::Pending
        {
            return Err(RunTransitionError::PendingOwnership);
        }
        self.child_pid = Some(child_pid);
        self.state = RunState::Running;
        Ok(())
    }

    /// Validates and marks a pending run for cleanup when execution is aborted before or during handoff.
    pub fn abort(
        &mut self,
        run_id: &str,
        wrapper_pid: u32,
        child_pid: Option<u32>,
    ) -> Result<(), RunTransitionError> {
        if self.run_id != run_id
            || self.wrapper_pid != wrapper_pid
            || self.child_pid.is_some()
            || self.state != RunState::Pending
        {
            return Err(RunTransitionError::PendingOwnership);
        }
        self.child_pid = child_pid;
        self.state = RunState::CleanupPending;
        Ok(())
    }

    /// Validates and marks a running invocation for cleanup after child process exit.
    pub fn finish(
        &mut self,
        run_id: &str,
        wrapper_pid: u32,
        child_pid: u32,
    ) -> Result<(), RunTransitionError> {
        if self.run_id != run_id
            || self.wrapper_pid != wrapper_pid
            || self.child_pid != Some(child_pid)
            || self.state != RunState::Running
        {
            return Err(RunTransitionError::ReleasedOwnership);
        }
        self.state = RunState::CleanupPending;
        Ok(())
    }

    /// Claims an abandoned run whose wrapper process is dead.
    pub fn claim_abandoned(&mut self, expected: &Self) -> Result<(), RunTransitionError> {
        if self != expected || !matches!(self.state, RunState::Pending | RunState::Running) {
            return Err(RunTransitionError::AbandonedRun);
        }
        self.state = RunState::CleanupPending;
        Ok(())
    }

    /// Validates that this record matches the expected snapshot and is ready for post-cleanup deletion.
    pub fn validate_cleanup_deletion(&self, expected: &Self) -> Result<(), RunTransitionError> {
        if self != expected || self.state != RunState::CleanupPending {
            return Err(RunTransitionError::CleanupDeletion);
        }
        Ok(())
    }
}

impl fmt::Debug for RunRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunRecord")
            .field("run_id", &self.run_id)
            .field("state", &self.state)
            .field("wrapper_pid", &self.wrapper_pid)
            .field("child_pid", &self.child_pid)
            .field("command", &"[REDACTED]")
            .field("profile", &self.profile)
            .field("source_profile", &self.source_profile)
            .field(
                "source_authority_fingerprint",
                &self.source_authority_fingerprint,
            )
            .field("github_user", &self.github_user)
            .field("repo_scope", &self.repo_scope)
            .field("expires_at", &self.expires_at)
            .field("access_token", &self.access_token)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(state: RunState) -> RunRecord {
        RunRecord {
            run_id: "run-42".into(),
            state,
            wrapper_pid: 1000,
            child_pid: if state == RunState::Running {
                Some(1001)
            } else {
                None
            },
            command: "secret-command --token xyz".into(),
            profile: "reader".into(),
            source_profile: "developer".into(),
            source_authority_fingerprint: "auth-fp".into(),
            github_user: "octocat".into(),
            repo_scope: "acme/api".into(),
            expires_at: TokenExpiry::parse("2026-08-09T11:00:00Z").unwrap(),
            access_token: AccessToken::from("run-secret-token"),
        }
    }

    #[test]
    fn activate_transitions_pending_to_running() {
        let mut record = sample_record(RunState::Pending);
        assert!(record.activate("run-42", 1000, 2000).is_ok());
        assert_eq!(record.state, RunState::Running);
        assert_eq!(record.child_pid, Some(2000));
    }

    #[test]
    fn activate_rejects_mismatched_ownership_leaving_record_unchanged() {
        let mut record = sample_record(RunState::Pending);

        // Wrong run_id
        assert_eq!(
            record.activate("wrong-id", 1000, 2000),
            Err(RunTransitionError::PendingOwnership)
        );
        assert_eq!(record.state, RunState::Pending);
        assert_eq!(record.child_pid, None);

        // Wrong wrapper_pid
        assert_eq!(
            record.activate("run-42", 9999, 2000),
            Err(RunTransitionError::PendingOwnership)
        );
        assert_eq!(record.state, RunState::Pending);

        // Already running
        record.state = RunState::Running;
        record.child_pid = Some(1001);
        assert_eq!(
            record.activate("run-42", 1000, 2000),
            Err(RunTransitionError::PendingOwnership)
        );
        assert_eq!(record.child_pid, Some(1001));
    }

    #[test]
    fn abort_transitions_pending_to_cleanup_pending() {
        let mut record = sample_record(RunState::Pending);
        assert!(record.abort("run-42", 1000, Some(2000)).is_ok());
        assert_eq!(record.state, RunState::CleanupPending);
        assert_eq!(record.child_pid, Some(2000));

        let mut record2 = sample_record(RunState::Pending);
        assert!(record2.abort("run-42", 1000, None).is_ok());
        assert_eq!(record2.state, RunState::CleanupPending);
        assert_eq!(record2.child_pid, None);
    }

    #[test]
    fn abort_rejects_mismatched_ownership_leaving_record_unchanged() {
        let mut record = sample_record(RunState::Running);
        assert_eq!(
            record.abort("run-42", 1000, None),
            Err(RunTransitionError::PendingOwnership)
        );
        assert_eq!(record.state, RunState::Running);
    }

    #[test]
    fn finish_transitions_running_to_cleanup_pending() {
        let mut record = sample_record(RunState::Running);
        assert!(record.finish("run-42", 1000, 1001).is_ok());
        assert_eq!(record.state, RunState::CleanupPending);
    }

    #[test]
    fn finish_rejects_mismatched_ownership_leaving_record_unchanged() {
        let mut record = sample_record(RunState::Running);

        // Wrong child PID
        assert_eq!(
            record.finish("run-42", 1000, 9999),
            Err(RunTransitionError::ReleasedOwnership)
        );
        assert_eq!(record.state, RunState::Running);

        // Wrong wrapper PID
        assert_eq!(
            record.finish("run-42", 9999, 1001),
            Err(RunTransitionError::ReleasedOwnership)
        );
        assert_eq!(record.state, RunState::Running);

        // Wrong state
        record.state = RunState::Pending;
        assert_eq!(
            record.finish("run-42", 1000, 1001),
            Err(RunTransitionError::ReleasedOwnership)
        );
        assert_eq!(record.state, RunState::Pending);
    }

    #[test]
    fn claim_abandoned_transitions_pending_or_running() {
        let mut pending = sample_record(RunState::Pending);
        let snapshot = sample_record(RunState::Pending);
        assert!(pending.claim_abandoned(&snapshot).is_ok());
        assert_eq!(pending.state, RunState::CleanupPending);

        let mut running = sample_record(RunState::Running);
        let running_snapshot = sample_record(RunState::Running);
        assert!(running.claim_abandoned(&running_snapshot).is_ok());
        assert_eq!(running.state, RunState::CleanupPending);
    }

    #[test]
    fn claim_abandoned_rejects_changed_record_or_cleanup_pending() {
        let mut running = sample_record(RunState::Running);
        let mut different_snapshot = sample_record(RunState::Running);
        different_snapshot.wrapper_pid = 9999;

        assert_eq!(
            running.claim_abandoned(&different_snapshot),
            Err(RunTransitionError::AbandonedRun)
        );
        assert_eq!(running.state, RunState::Running);

        let mut already_cleanup = sample_record(RunState::CleanupPending);
        let cleanup_snapshot = sample_record(RunState::CleanupPending);
        assert_eq!(
            already_cleanup.claim_abandoned(&cleanup_snapshot),
            Err(RunTransitionError::AbandonedRun)
        );
    }

    #[test]
    fn validate_cleanup_deletion_requires_matching_cleanup_pending() {
        let cleanup = sample_record(RunState::CleanupPending);
        assert!(cleanup.validate_cleanup_deletion(&cleanup).is_ok());

        let running = sample_record(RunState::Running);
        assert_eq!(
            running.validate_cleanup_deletion(&running),
            Err(RunTransitionError::CleanupDeletion)
        );

        let mut different = sample_record(RunState::CleanupPending);
        different.wrapper_pid = 9999;
        assert_eq!(
            cleanup.validate_cleanup_deletion(&different),
            Err(RunTransitionError::CleanupDeletion)
        );
    }

    #[test]
    fn run_record_debug_redacts_both_command_and_token() {
        let record = sample_record(RunState::Pending);
        let debug = format!("{record:?}");
        assert!(!debug.contains("secret-command"));
        assert!(!debug.contains("xyz"));
        assert!(!debug.contains("run-secret-token"));
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("run-42"));
        assert!(debug.contains("1000"));
    }
}
