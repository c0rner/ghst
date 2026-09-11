use crate::credential::store::{IssuanceGuard, SourceGuard};
use crate::run::RunRecord;

/// Outcome of committing a pending run recovery record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingRunOutcome {
    Saved,
    EpochChanged,
    BaseGenerationChanged,
}

/// Trait for persisting initial pending run recovery records.
pub trait PendingRunStore {
    type Error: std::error::Error + 'static;

    fn commit_pending(
        &self,
        candidate: &RunRecord,
        guard: IssuanceGuard,
        source_guard: &SourceGuard<'_>,
    ) -> Result<PendingRunOutcome, Self::Error>;
}

/// Trait for run lifecycle state transitions and recovery deletion.
pub trait RunLifecycleStore {
    type Error: std::error::Error + 'static;

    fn activate(
        &self,
        run_id: &str,
        wrapper_pid: u32,
        child_pid: u32,
    ) -> Result<RunRecord, Self::Error>;

    fn abort(
        &self,
        run_id: &str,
        wrapper_pid: u32,
        child_pid: Option<u32>,
    ) -> Result<RunRecord, Self::Error>;

    fn finish(
        &self,
        run_id: &str,
        wrapper_pid: u32,
        child_pid: u32,
    ) -> Result<RunRecord, Self::Error>;

    fn claim_abandoned(&self, expected: &RunRecord) -> Result<RunRecord, Self::Error>;

    fn delete_cleanup_pending(&self, expected: &RunRecord) -> Result<bool, Self::Error>;
}
