use super::CacheError;
use crate::run::RunRecord;
use std::path::Path;

pub fn activate(
    cache_dir: &Path,
    cache_key: &str,
    run_id: &str,
    wrapper_pid: u32,
    child_pid: u32,
) -> Result<RunRecord, CacheError> {
    super::storage::update_run(cache_dir, cache_key, |entry| {
        entry
            .activate(run_id, wrapper_pid, child_pid)
            .map_err(CacheError::from)
    })
}

pub fn abort(
    cache_dir: &Path,
    cache_key: &str,
    run_id: &str,
    wrapper_pid: u32,
    child_pid: Option<u32>,
) -> Result<RunRecord, CacheError> {
    super::storage::update_run(cache_dir, cache_key, |entry| {
        entry
            .abort(run_id, wrapper_pid, child_pid)
            .map_err(CacheError::from)
    })
}

pub fn finish(
    cache_dir: &Path,
    cache_key: &str,
    run_id: &str,
    wrapper_pid: u32,
    child_pid: u32,
) -> Result<RunRecord, CacheError> {
    super::storage::update_run(cache_dir, cache_key, |entry| {
        entry
            .finish(run_id, wrapper_pid, child_pid)
            .map_err(CacheError::from)
    })
}
