use super::{CacheError, RunCacheEntry};
use crate::run::lifecycle::RunOwner;
use std::path::Path;

pub fn activate(
    cache_dir: &Path,
    cache_key: &str,
    run_id: &str,
    wrapper_pid: u32,
    child_pid: u32,
) -> Result<RunCacheEntry, CacheError> {
    super::storage::update_run(cache_dir, cache_key, |entry| {
        let phase = entry.lifecycle().activate(
            RunOwner {
                run_id,
                wrapper_pid,
            },
            child_pid,
        )?;
        entry.phase = phase;
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
        let phase = entry.lifecycle().abort(
            RunOwner {
                run_id,
                wrapper_pid,
            },
            child_pid,
        )?;
        entry.phase = phase;
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
        let phase = entry.lifecycle().finish(
            RunOwner {
                run_id,
                wrapper_pid,
            },
            child_pid,
        )?;
        entry.phase = phase;
        Ok(())
    })
}
