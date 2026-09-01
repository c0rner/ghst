use super::{CacheError, RunCacheEntry, RunState};
use std::path::Path;

pub fn activate(
    cache_dir: &Path,
    cache_key: &str,
    run_id: &str,
    wrapper_pid: u32,
    child_pid: u32,
) -> Result<RunCacheEntry, CacheError> {
    super::storage::update_run(cache_dir, cache_key, |entry| {
        if entry.run_id != run_id
            || entry.wrapper_pid != wrapper_pid
            || entry.child_pid.is_some()
            || entry.state != RunState::Pending
        {
            return Err(CacheError::InvalidRunTransition(
                "pending run ownership did not match",
            ));
        }
        entry.child_pid = Some(child_pid);
        entry.state = RunState::Running;
        Ok(())
    })
}

pub fn abort(
    cache_dir: &Path,
    cache_key: &str,
    run_id: &str,
    wrapper_pid: u32,
    child_pid: Option<u32>,
) -> Result<RunCacheEntry, CacheError> {
    super::storage::update_run(cache_dir, cache_key, |entry| {
        if entry.run_id != run_id
            || entry.wrapper_pid != wrapper_pid
            || entry.child_pid.is_some()
            || entry.state != RunState::Pending
        {
            return Err(CacheError::InvalidRunTransition(
                "pending run ownership did not match",
            ));
        }
        entry.child_pid = child_pid;
        entry.state = RunState::CleanupPending;
        Ok(())
    })
}

pub fn finish(
    cache_dir: &Path,
    cache_key: &str,
    run_id: &str,
    wrapper_pid: u32,
    child_pid: u32,
) -> Result<RunCacheEntry, CacheError> {
    super::storage::update_run(cache_dir, cache_key, |entry| {
        if entry.run_id != run_id
            || entry.wrapper_pid != wrapper_pid
            || entry.child_pid != Some(child_pid)
            || entry.state != RunState::Running
        {
            return Err(CacheError::InvalidRunTransition(
                "released run ownership did not match",
            ));
        }
        entry.state = RunState::CleanupPending;
        Ok(())
    })
}
