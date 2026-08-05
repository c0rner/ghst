use crate::cache::error::CacheError;
use crate::cache::fs::{
    LockMode, cache_dir_exists, cache_file_path, create_private_tempfile, ensure_cache_dir,
    increment_epoch, open_private_file, read_epoch, sync_cache_dir, validate_cache_file,
    with_cache_lock, with_locked_file,
};
use crate::cache::key::{compute_cache_key, validate_cache_key};
use crate::cache::types::{CacheEntry, SaveCacheEntry};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub enum CacheInspectionState {
    Current(CacheEntry),
    Unsupported(CacheEntry),
    Invalid,
}

pub struct CacheInspection {
    path: PathBuf,
    pub label: String,
    pub state: CacheInspectionState,
}

pub struct ClearTransaction {
    entries: Vec<CacheInspection>,
    deleted: bool,
}

impl ClearTransaction {
    pub fn entries(&self) -> &[CacheInspection] {
        &self.entries
    }

    pub fn delete(&mut self, index: usize) -> Result<bool, CacheError> {
        let path = &self.entries[index].path;
        match fs::symlink_metadata(path) {
            Ok(_) => {
                fs::remove_file(path).map_err(CacheError::Io)?;
                self.deleted = true;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(CacheError::Io(error)),
        }
    }
}

pub fn inspect_cache(cache_dir: &Path) -> Result<Vec<CacheInspection>, CacheError> {
    if !cache_dir_exists(cache_dir)? {
        return Ok(Vec::new());
    }
    with_cache_lock(cache_dir, LockMode::Shared, || inspect_unlocked(cache_dir))
}

pub fn clear_transaction<T>(
    cache_dir: &Path,
    operation: impl FnOnce(&mut ClearTransaction) -> T,
) -> Result<T, CacheError> {
    with_locked_file(cache_dir, LockMode::Exclusive, |lock| {
        increment_epoch(lock)?;
        let entries = inspect_unlocked(cache_dir)?;
        let mut transaction = ClearTransaction {
            entries,
            deleted: false,
        };
        let result = operation(&mut transaction);
        if transaction.deleted {
            sync_cache_dir(cache_dir)?;
        }
        Ok(result)
    })
}

fn inspect_unlocked(cache_dir: &Path) -> Result<Vec<CacheInspection>, CacheError> {
    let mut entries = Vec::new();
    for item in fs::read_dir(cache_dir).map_err(CacheError::Io)? {
        let item = item.map_err(CacheError::Io)?;
        let path = item.path();
        if path.extension() != Some(OsStr::new("json")) {
            continue;
        }
        let label = item
            .file_name()
            .to_string_lossy()
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                    character
                } else {
                    '?'
                }
            })
            .collect();
        let state = match read_cache_entry(&path) {
            Ok(Some(entry)) => {
                let key = path.file_stem().and_then(|value| value.to_str());
                let consistent = key.is_some_and(|key| {
                    validate_cache_key(key).is_ok() && validate_entry_key(key, &entry).is_ok()
                });
                if !consistent {
                    CacheInspectionState::Invalid
                } else if entry.is_current() {
                    CacheInspectionState::Current(entry)
                } else {
                    CacheInspectionState::Unsupported(entry)
                }
            }
            Ok(None) | Err(_) => CacheInspectionState::Invalid,
        };
        entries.push(CacheInspection { path, label, state });
    }
    entries.sort_by(|left, right| left.label.cmp(&right.label));
    Ok(entries)
}

/// Saves a `CacheEntry` to `cache_dir/<hash_key>.json`.
///
/// A compatible current entry is retained. A legacy, expired, or same-kind
/// stale-provenance entry is atomically replaced. Malformed, inconsistent, or
/// wrong-kind entries fail closed.
#[cfg_attr(not(test), allow(dead_code))]
pub fn save_cache_entry(
    cache_dir: &Path,
    hash_key: &str,
    entry: &CacheEntry,
) -> Result<SaveCacheEntry, CacheError> {
    ensure_cache_dir(cache_dir)?;
    validate_entry_key(hash_key, entry)?;
    let json_bytes = serde_json::to_vec_pretty(entry).map_err(CacheError::Json)?;

    with_cache_lock(cache_dir, LockMode::Exclusive, || {
        save_unlocked(cache_dir, hash_key, entry, &json_bytes)
    })
}

pub fn save_cache_candidate(
    cache_dir: &Path,
    hash_key: &str,
    entry: &CacheEntry,
    epoch: u64,
    expected_root: Option<(&str, &str)>,
) -> Result<SaveCacheEntry, CacheError> {
    ensure_cache_dir(cache_dir)?;
    validate_entry_key(hash_key, entry)?;
    let json_bytes = serde_json::to_vec_pretty(entry).map_err(CacheError::Json)?;
    with_locked_file(cache_dir, LockMode::Exclusive, |lock| {
        let actual = read_epoch(lock)?;
        if actual != epoch {
            return Err(CacheError::EpochChanged {
                expected: epoch,
                actual,
            });
        }
        if let Some((root_key, generation)) = expected_root {
            let root = read_cache_entry(&cache_file_path(cache_dir, root_key))?;
            if !matches!(root, Some(CacheEntry::Root(ref root)) if root.generation_fingerprint() == generation)
            {
                return Err(CacheError::RootGenerationChanged);
            }
        }
        save_unlocked(cache_dir, hash_key, entry, &json_bytes)
    })
}

fn save_unlocked(
    cache_dir: &Path,
    hash_key: &str,
    entry: &CacheEntry,
    json_bytes: &[u8],
) -> Result<SaveCacheEntry, CacheError> {
    let cache_file = cache_file_path(cache_dir, hash_key);
    if let Some(existing) = read_cache_entry(&cache_file)? {
        validate_entry_key(hash_key, &existing)?;
        if existing.kind_name() != entry.kind_name() {
            return Err(CacheError::UnexpectedKind {
                expected: entry.kind_name(),
                actual: existing.kind_name(),
            });
        }
        if existing.compatible_with(entry, time::OffsetDateTime::now_utc()) {
            return Ok(SaveCacheEntry::Retained(Box::new(existing)));
        }
    }
    persist_cache_file(cache_dir, &cache_file, json_bytes)?;
    Ok(SaveCacheEntry::Saved)
}

fn persist_cache_file(
    cache_dir: &Path,
    cache_file: &Path,
    json_bytes: &[u8],
) -> Result<(), CacheError> {
    let mut temporary = create_private_tempfile(cache_dir)?;
    temporary
        .as_file_mut()
        .write_all(json_bytes)
        .map_err(CacheError::Io)?;
    temporary.as_file_mut().sync_all().map_err(CacheError::Io)?;
    temporary
        .persist(cache_file)
        .map_err(|error| CacheError::Io(error.error))?;
    sync_cache_dir(cache_dir)?;

    let metadata = fs::symlink_metadata(cache_file).map_err(CacheError::Io)?;
    validate_cache_file(cache_file, &metadata)
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
#[cfg_attr(not(test), allow(dead_code))]
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
#[cfg(test)]
pub fn list_cache_entries(cache_dir: &Path) -> Result<Vec<(String, CacheEntry)>, CacheError> {
    let raw = list_all_cache_entries(cache_dir)?;
    let mut valid = Vec::new();
    for (key, item) in raw {
        valid.push((key, item?));
    }
    Ok(valid)
}

#[cfg(test)]
pub type CacheFileEntries = Vec<(String, Result<CacheEntry, CacheError>)>;

/// Lists all cache entry files in `cache_dir`, returning `(hash_key, Result<CacheEntry, CacheError>)`.
#[cfg(test)]
pub fn list_all_cache_entries(cache_dir: &Path) -> Result<CacheFileEntries, CacheError> {
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

            let Some(hash_key) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            if validate_cache_key(hash_key).is_err() {
                continue;
            }

            let entry_result = match read_cache_entry(&path) {
                Ok(Some(entry)) => Ok(entry),
                Ok(None) => continue,
                Err(err) => Err(err),
            };

            entries.push((hash_key.to_string(), entry_result));
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
