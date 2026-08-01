use crate::cache::error::CacheError;
use crate::cache::fs::{
    LockMode, cache_dir_exists, create_private_tempfile, ensure_cache_dir, open_private_file,
    sync_cache_dir, validate_cache_file, with_cache_lock,
};
use crate::cache::key::validate_cache_key;
use crate::cache::types::{CacheEntry, SaveCacheEntry};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

/// Saves a `CacheEntry` to `cache_dir/<hash_key>.json`.
///
/// A valid existing entry is retained. An expired entry is atomically replaced.
pub fn save_cache_entry(
    cache_dir: &Path,
    hash_key: &str,
    entry: &CacheEntry,
) -> Result<SaveCacheEntry, CacheError> {
    ensure_cache_dir(cache_dir)?;
    let json_bytes = serde_json::to_vec_pretty(entry).map_err(CacheError::Json)?;

    with_cache_lock(cache_dir, hash_key, LockMode::Exclusive, |cache_file| {
        if let Some(existing) = read_cache_entry(cache_file)? {
            if !existing.is_expired()? {
                return Ok(SaveCacheEntry::Retained(existing));
            }
        }

        let mut temporary = create_private_tempfile(cache_dir)?;
        temporary
            .as_file_mut()
            .write_all(&json_bytes)
            .map_err(CacheError::Io)?;
        temporary.as_file_mut().sync_all().map_err(CacheError::Io)?;
        temporary
            .persist(cache_file)
            .map_err(|err| CacheError::Io(err.error))?;
        sync_cache_dir(cache_dir)?;

        let metadata = fs::symlink_metadata(cache_file).map_err(CacheError::Io)?;
        validate_cache_file(cache_file, &metadata)?;

        Ok(SaveCacheEntry::Saved)
    })
}

/// Loads a `CacheEntry` from `cache_dir/<hash_key>.json`.
pub fn load_cache_entry(
    cache_dir: &Path,
    hash_key: &str,
) -> Result<Option<CacheEntry>, CacheError> {
    if !cache_dir_exists(cache_dir)? {
        return Ok(None);
    }

    with_cache_lock(cache_dir, hash_key, LockMode::Shared, read_cache_entry)
}

/// Deletes a cache entry file `cache_dir/<hash_key>.json`.
#[allow(dead_code)]
pub fn delete_cache_entry(cache_dir: &Path, hash_key: &str) -> Result<bool, CacheError> {
    if !cache_dir_exists(cache_dir)? {
        return Ok(false);
    }

    with_cache_lock(cache_dir, hash_key, LockMode::Exclusive, |cache_file| {
        match fs::symlink_metadata(cache_file) {
            Ok(metadata) => {
                validate_cache_file(cache_file, &metadata)?;
                fs::remove_file(cache_file).map_err(CacheError::Io)?;
                Ok(true)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(CacheError::Io(err)),
        }
    })
}

/// Lists all `(hash_key, CacheEntry)` pairs stored in `cache_dir`.
#[allow(dead_code)]
pub fn list_cache_entries(cache_dir: &Path) -> Result<Vec<(String, CacheEntry)>, CacheError> {
    let mut entries = Vec::new();
    if !cache_dir_exists(cache_dir)? {
        return Ok(entries);
    }

    let read_dir = fs::read_dir(cache_dir).map_err(CacheError::Io)?;
    for entry in read_dir {
        let entry = entry.map_err(CacheError::Io)?;
        let path = entry.path();
        if path.extension() != Some(OsStr::new("json")) {
            continue;
        }

        let hash_key = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| CacheError::InsecurePath {
                path: path.clone(),
                reason: "cache entry name is not valid UTF-8",
            })?;
        validate_cache_key(hash_key)?;

        if let Some(cache_entry) =
            with_cache_lock(cache_dir, hash_key, LockMode::Shared, read_cache_entry)?
        {
            entries.push((hash_key.to_string(), cache_entry));
        }
    }

    Ok(entries)
}

pub fn read_cache_entry(cache_file: &Path) -> Result<Option<CacheEntry>, CacheError> {
    match fs::symlink_metadata(cache_file) {
        Ok(metadata) => {
            validate_cache_file(cache_file, &metadata)?;
            let mut content = String::new();
            open_private_file(cache_file, false)?
                .read_to_string(&mut content)
                .map_err(CacheError::Io)?;
            serde_json::from_str(&content)
                .map(Some)
                .map_err(CacheError::Json)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(CacheError::Io(err)),
    }
}
