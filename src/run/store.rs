use super::lifecycle::RunOwner;
use crate::credential::{store::StoreError, stored::StoredRun};
/// Atomically validates ownership or the exact recovery snapshot, applies a lifecycle
/// transition, and persists it before returning. Cleanup deletion requires that exact claim.
pub trait RunStore {
    fn activate(
        &self,
        key: &str,
        owner: RunOwner<'_>,
        child_pid: u32,
    ) -> Result<StoredRun, StoreError>;
    fn abort(
        &self,
        key: &str,
        owner: RunOwner<'_>,
        child_pid: Option<u32>,
    ) -> Result<StoredRun, StoreError>;
    fn finish(
        &self,
        key: &str,
        owner: RunOwner<'_>,
        child_pid: u32,
    ) -> Result<StoredRun, StoreError>;
    fn claim_abandoned(&self, key: &str, expected: &StoredRun) -> Result<StoredRun, StoreError>;
    fn delete_cleaned(&self, key: &str, expected: &StoredRun) -> Result<bool, StoreError>;
}
