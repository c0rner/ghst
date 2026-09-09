use crate::cache::error::CacheError;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const CACHE_LOCK_FILE: &str = ".cache.lock";

#[derive(Clone, Copy)]
pub(super) enum LockMode {
    Shared,
    Exclusive,
}

/// Ensures that the cache directory exists and has private permissions.
pub fn ensure_cache_dir(cache_dir: &Path) -> Result<(), CacheError> {
    if !crate::fs::symlink_exists(cache_dir).map_err(CacheError::from)? {
        crate::fs::create_private_dir(cache_dir).map_err(CacheError::from)?;
    }
    crate::fs::validate_private_dir(cache_dir).map_err(CacheError::from)
}

pub(super) fn cache_dir_exists(cache_dir: &Path) -> Result<bool, CacheError> {
    if !crate::fs::symlink_exists(cache_dir).map_err(CacheError::from)? {
        return Ok(false);
    }
    crate::fs::validate_private_dir(cache_dir).map_err(CacheError::from)?;
    Ok(true)
}

pub(super) fn with_cache_lock<T>(
    cache_dir: &Path,
    lock_mode: LockMode,
    operation: impl FnOnce() -> Result<T, CacheError>,
) -> Result<T, CacheError> {
    with_locked_file(cache_dir, lock_mode, |_| operation())
}

pub fn cache_epoch(cache_dir: &Path) -> Result<u64, CacheError> {
    with_locked_file(cache_dir, LockMode::Shared, read_epoch)
}

pub(super) fn with_locked_file<T>(
    cache_dir: &Path,
    mode: LockMode,
    operation: impl FnOnce(&mut File) -> Result<T, CacheError>,
) -> Result<T, CacheError> {
    ensure_cache_dir(cache_dir)?;
    let mut file = open_cache_lock_file(cache_dir)?;
    match mode {
        LockMode::Shared => fs2::FileExt::lock_shared(&file).map_err(CacheError::descriptor_io)?,
        LockMode::Exclusive => {
            fs2::FileExt::lock_exclusive(&file).map_err(CacheError::descriptor_io)?;
        }
    }
    operation(&mut file)
}

pub(super) fn read_epoch(file: &mut File) -> Result<u64, CacheError> {
    file.seek(SeekFrom::Start(0))
        .map_err(CacheError::descriptor_io)?;
    let mut value = String::new();
    file.read_to_string(&mut value)
        .map_err(CacheError::descriptor_io)?;
    if value.is_empty() {
        return Ok(0);
    }
    value.trim().parse().map_err(|_| CacheError::MalformedEpoch)
}

pub(super) fn increment_epoch(file: &mut File) -> Result<u64, CacheError> {
    let epoch = read_epoch(file)?
        .checked_add(1)
        .ok_or(CacheError::EpochExhausted)?;
    file.set_len(0).map_err(CacheError::descriptor_io)?;
    file.seek(SeekFrom::Start(0))
        .map_err(CacheError::descriptor_io)?;
    writeln!(file, "{epoch}").map_err(CacheError::descriptor_io)?;
    file.sync_all().map_err(CacheError::descriptor_io)?;
    Ok(epoch)
}

fn open_cache_lock_file(cache_dir: &Path) -> Result<File, CacheError> {
    let lock_path = cache_dir.join(CACHE_LOCK_FILE);
    crate::fs::open_private_lock_file(&lock_path).map_err(CacheError::from)
}
