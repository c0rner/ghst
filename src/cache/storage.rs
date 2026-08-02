use crate::cache::error::CacheError;
use crate::cache::fs::{
    LockMode, cache_dir_exists, cache_file_path, create_private_tempfile, ensure_cache_dir,
    open_private_file, sync_cache_dir, validate_cache_file, with_cache_lock,
};
use crate::cache::key::{compute_cache_key, validate_cache_key};
use crate::cache::types::{CacheEntry, SaveCacheEntry};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

/// Saves a `CacheEntry` to `cache_dir/<hash_key>.json`.
///
/// A compatible current entry is retained. A legacy, expired, or same-kind
/// stale-provenance entry is atomically replaced. Malformed, inconsistent, or
/// wrong-kind entries fail closed.
pub fn save_cache_entry(
    cache_dir: &Path,
    hash_key: &str,
    entry: &CacheEntry,
) -> Result<SaveCacheEntry, CacheError> {
    ensure_cache_dir(cache_dir)?;
    validate_entry_key(hash_key, entry)?;
    let json_bytes = serde_json::to_vec_pretty(entry).map_err(CacheError::Json)?;

    with_cache_lock(cache_dir, LockMode::Exclusive, || {
        let cache_file = cache_file_path(cache_dir, hash_key);
        if let Some(existing) = read_cache_entry(&cache_file)? {
            validate_entry_key(hash_key, &existing)?;
            if existing.kind() != entry.kind() {
                return Err(CacheError::UnexpectedKind {
                    expected: kind_name(entry),
                    actual: kind_name(&existing),
                });
            }
            if existing.compatible_with(entry, time::OffsetDateTime::now_utc()) {
                return Ok(SaveCacheEntry::Retained(Box::new(existing)));
            }
        }

        let mut temporary = create_private_tempfile(cache_dir)?;
        temporary
            .as_file_mut()
            .write_all(&json_bytes)
            .map_err(CacheError::Io)?;
        temporary.as_file_mut().sync_all().map_err(CacheError::Io)?;
        temporary
            .persist(&cache_file)
            .map_err(|err| CacheError::Io(err.error))?;
        sync_cache_dir(cache_dir)?;

        let metadata = fs::symlink_metadata(&cache_file).map_err(CacheError::Io)?;
        validate_cache_file(&cache_file, &metadata)?;

        Ok(SaveCacheEntry::Saved)
    })
}

fn validate_entry_key(hash_key: &str, entry: &CacheEntry) -> Result<(), CacheError> {
    let actual_key = compute_cache_key(entry.profile(), entry.repo_scope());
    if actual_key == hash_key {
        Ok(())
    } else {
        Err(CacheError::InconsistentMetadata {
            expected_key: hash_key.to_owned(),
            actual_key,
        })
    }
}

const fn kind_name(entry: &CacheEntry) -> &'static str {
    match entry.kind() {
        crate::cache::types::CacheKind::Root => "root",
        crate::cache::types::CacheKind::Derived => "derived",
    }
}

/// Loads a `CacheEntry` from `cache_dir/<hash_key>.json`.
pub fn load_cache_entry(
    cache_dir: &Path,
    hash_key: &str,
) -> Result<Option<CacheEntry>, CacheError> {
    if !cache_dir_exists(cache_dir)? {
        return Ok(None);
    }

    validate_cache_key(hash_key)?;
    with_cache_lock(cache_dir, LockMode::Shared, || {
        read_cache_entry(&cache_file_path(cache_dir, hash_key))
    })
}

/// Deletes a cache entry file `cache_dir/<hash_key>.json`.
#[allow(dead_code)]
pub fn delete_cache_entry(cache_dir: &Path, hash_key: &str) -> Result<bool, CacheError> {
    if !cache_dir_exists(cache_dir)? {
        return Ok(false);
    }

    validate_cache_key(hash_key)?;
    with_cache_lock(cache_dir, LockMode::Exclusive, || {
        let cache_file = cache_file_path(cache_dir, hash_key);
        match fs::symlink_metadata(&cache_file) {
            Ok(metadata) => {
                validate_cache_file(&cache_file, &metadata)?;
                fs::remove_file(&cache_file).map_err(CacheError::Io)?;
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
    if !cache_dir_exists(cache_dir)? {
        return Ok(Vec::new());
    }

    with_cache_lock(cache_dir, LockMode::Shared, || {
        let mut entries = Vec::new();
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

            if let Some(cache_entry) = read_cache_entry(&path)? {
                entries.push((hash_key.to_string(), cache_entry));
            }
        }

        Ok(entries)
    })
}

fn read_cache_entry(cache_file: &Path) -> Result<Option<CacheEntry>, CacheError> {
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
