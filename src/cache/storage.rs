use crate::cache::error::CacheError;
use crate::cache::fs::{
    LockMode, cache_dir_exists, cache_file_path, create_private_tempfile, ensure_cache_dir,
    increment_epoch, open_private_file, read_epoch, sync_cache_dir, validate_cache_file,
    with_cache_lock, with_locked_file,
};
use crate::cache::key::{compute_cache_key, compute_run_cache_key, validate_cache_key};
use crate::cache::types::{CacheEntry, ReplaceCacheEntry, RunCacheEntry, RunState, SaveCacheEntry};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub enum CacheInspectionState {
    Current(Box<CacheEntry>),
    Invalid,
}

pub struct CacheInspection {
    path: PathBuf,
    pub label: String,
    pub cache_key: Option<String>,
    pub state: CacheInspectionState,
}

pub struct RevokeTransaction {
    entries: Vec<CacheInspection>,
    deleted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteRootOutcome {
    Deleted,
    Missing,
    Changed,
}

impl RevokeTransaction {
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
    with_cache_lock(cache_dir, LockMode::Exclusive, || {
        inspect_unlocked(cache_dir)
    })
}

pub fn revoke_transaction<T>(
    cache_dir: &Path,
    operation: impl FnOnce(&mut RevokeTransaction) -> T,
) -> Result<T, CacheError> {
    with_locked_file(cache_dir, LockMode::Exclusive, |lock| {
        increment_epoch(lock)?;
        let entries = inspect_unlocked(cache_dir)?;
        let mut transaction = RevokeTransaction {
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
        let cache_key = path
            .file_stem()
            .and_then(|value| value.to_str())
            .filter(|value| validate_cache_key(value).is_ok())
            .map(str::to_owned);
        let state = match read_cache_entry(&path) {
            Ok(Some(entry)) => {
                let consistent = cache_key
                    .as_deref()
                    .is_some_and(|key| validate_entry_key(key, &entry).is_ok());
                if consistent {
                    CacheInspectionState::Current(Box::new(entry))
                } else {
                    CacheInspectionState::Invalid
                }
            }
            Ok(None) => continue,
            Err(error) => {
                tracing::debug!(path = %path.display(), error = %error, "failed to inspect cache entry");
                CacheInspectionState::Invalid
            }
        };
        entries.push(CacheInspection {
            path,
            label,
            cache_key,
            state,
        });
    }
    entries.sort_by(|left, right| left.label.cmp(&right.label));
    Ok(entries)
}

/// Saves a `CacheEntry` to `cache_dir/<hash_key>.json`.
///
/// A compatible current entry is retained. An expired or same-kind
/// stale-provenance entry is atomically replaced. Malformed, inconsistent, or
/// wrong-kind entries fail closed. Unsupported schemas are discarded.
#[cfg(test)]
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

/// Replaces the exact derived entry selected for renewal under the cache lock.
///
/// A compatible entry written by a concurrent renewal is retained instead. The
/// caller owns cleanup of either the displaced token or its unused candidate.
pub fn replace_cache_candidate(
    cache_dir: &Path,
    hash_key: &str,
    expected: &CacheEntry,
    candidate: &CacheEntry,
    epoch: u64,
    expected_root: (&str, &str),
    now: time::OffsetDateTime,
) -> Result<ReplaceCacheEntry, CacheError> {
    ensure_cache_dir(cache_dir)?;
    validate_entry_key(hash_key, expected)?;
    validate_entry_key(hash_key, candidate)?;
    if !matches!(expected, CacheEntry::Derived(_)) || !matches!(candidate, CacheEntry::Derived(_)) {
        return Err(CacheError::UnexpectedKind {
            expected: "derived",
            actual: candidate.kind_name(),
        });
    }
    let json_bytes = serde_json::to_vec_pretty(candidate).map_err(CacheError::Json)?;
    with_locked_file(cache_dir, LockMode::Exclusive, |lock| {
        let actual = read_epoch(lock)?;
        if actual != epoch {
            return Err(CacheError::EpochChanged {
                expected: epoch,
                actual,
            });
        }
        let (root_key, generation) = expected_root;
        let root = read_cache_entry(&cache_file_path(cache_dir, root_key))?;
        if !matches!(root, Some(CacheEntry::Root(ref root)) if root.generation_fingerprint() == generation)
        {
            return Err(CacheError::RootGenerationChanged);
        }

        let cache_file = cache_file_path(cache_dir, hash_key);
        let current = read_cache_entry(&cache_file)?.ok_or(CacheError::RenewalEntryChanged)?;
        validate_entry_key(hash_key, &current)?;
        if &current == expected {
            persist_cache_file(cache_dir, &cache_file, &json_bytes)?;
            return Ok(ReplaceCacheEntry::Replaced(Box::new(current)));
        }
        if current.compatible_with(candidate, now) {
            return Ok(ReplaceCacheEntry::Retained(Box::new(current)));
        }
        Err(CacheError::RenewalEntryChanged)
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
        if matches!(&existing, CacheEntry::Run(_)) {
            return Err(CacheError::RunCollision(hash_key.to_owned()));
        }
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
    let actual_key = match entry {
        CacheEntry::Root(_) | CacheEntry::Derived(_) => {
            compute_cache_key(entry.profile(), entry.repo_scope())
        }
        CacheEntry::Run(entry) => compute_run_cache_key(&entry.run_id),
    };
    if actual_key == hash_key {
        Ok(())
    } else {
        Err(CacheError::InconsistentMetadata {
            expected_key: hash_key.to_owned(),
            actual_key,
        })
    }
}

pub fn transition_run_to_running(
    cache_dir: &Path,
    cache_key: &str,
    run_id: &str,
    wrapper_pid: u32,
    child_pid: u32,
) -> Result<RunCacheEntry, CacheError> {
    update_run(cache_dir, cache_key, |entry| {
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

pub fn mark_pending_run_for_cleanup(
    cache_dir: &Path,
    cache_key: &str,
    run_id: &str,
    wrapper_pid: u32,
    child_pid: Option<u32>,
) -> Result<RunCacheEntry, CacheError> {
    update_run(cache_dir, cache_key, |entry| {
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

pub fn claim_released_run(
    cache_dir: &Path,
    cache_key: &str,
    run_id: &str,
    wrapper_pid: u32,
    child_pid: u32,
) -> Result<RunCacheEntry, CacheError> {
    update_run(cache_dir, cache_key, |entry| {
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

pub fn claim_abandoned_run(
    cache_dir: &Path,
    cache_key: &str,
    expected: &RunCacheEntry,
) -> Result<RunCacheEntry, CacheError> {
    update_run(cache_dir, cache_key, |entry| {
        if entry != expected || !matches!(entry.state, RunState::Pending | RunState::Running) {
            return Err(CacheError::InvalidRunTransition(
                "abandoned run changed while checking liveness",
            ));
        }
        entry.state = RunState::CleanupPending;
        Ok(())
    })
}

pub fn delete_run_after_cleanup(
    cache_dir: &Path,
    cache_key: &str,
    expected: &RunCacheEntry,
) -> Result<bool, CacheError> {
    if !cache_dir_exists(cache_dir)? {
        return Ok(false);
    }
    validate_cache_key(cache_key)?;
    with_cache_lock(cache_dir, LockMode::Exclusive, || {
        let path = cache_file_path(cache_dir, cache_key);
        let Some(entry) = read_cache_entry(&path)? else {
            return Ok(false);
        };
        validate_entry_key(cache_key, &entry)?;
        match entry {
            CacheEntry::Run(entry)
                if entry == *expected && entry.state == RunState::CleanupPending =>
            {
                fs::remove_file(path).map_err(CacheError::Io)?;
                sync_cache_dir(cache_dir)?;
                Ok(true)
            }
            CacheEntry::Run(_) => Err(CacheError::InvalidRunTransition(
                "cleanup deletion ownership did not match",
            )),
            other => Err(CacheError::UnexpectedKind {
                expected: "run",
                actual: other.kind_name(),
            }),
        }
    })
}

pub fn delete_entry_if_unchanged(
    cache_dir: &Path,
    cache_key: &str,
    expected: &CacheEntry,
) -> Result<bool, CacheError> {
    if !cache_dir_exists(cache_dir)? {
        return Ok(false);
    }
    validate_cache_key(cache_key)?;
    with_cache_lock(cache_dir, LockMode::Exclusive, || {
        let path = cache_file_path(cache_dir, cache_key);
        let Some(entry) = read_cache_entry(&path)? else {
            return Ok(false);
        };
        validate_entry_key(cache_key, &entry)?;
        if &entry != expected {
            return Ok(false);
        }
        fs::remove_file(path).map_err(CacheError::Io)?;
        sync_cache_dir(cache_dir)?;
        Ok(true)
    })
}

pub fn delete_root_if_generation(
    cache_dir: &Path,
    cache_key: &str,
    expected_generation: &str,
) -> Result<DeleteRootOutcome, CacheError> {
    if !cache_dir_exists(cache_dir)? {
        return Ok(DeleteRootOutcome::Missing);
    }
    validate_cache_key(cache_key)?;
    with_cache_lock(cache_dir, LockMode::Exclusive, || {
        let path = cache_file_path(cache_dir, cache_key);
        let Some(entry) = read_cache_entry(&path)? else {
            return Ok(DeleteRootOutcome::Missing);
        };
        validate_entry_key(cache_key, &entry)?;
        match entry {
            CacheEntry::Root(entry) if entry.generation_fingerprint() == expected_generation => {
                fs::remove_file(path).map_err(CacheError::Io)?;
                sync_cache_dir(cache_dir)?;
                Ok(DeleteRootOutcome::Deleted)
            }
            CacheEntry::Root(_) => Ok(DeleteRootOutcome::Changed),
            other => Err(CacheError::UnexpectedKind {
                expected: "root",
                actual: other.kind_name(),
            }),
        }
    })
}

fn update_run(
    cache_dir: &Path,
    cache_key: &str,
    operation: impl FnOnce(&mut RunCacheEntry) -> Result<(), CacheError>,
) -> Result<RunCacheEntry, CacheError> {
    ensure_cache_dir(cache_dir)?;
    validate_cache_key(cache_key)?;
    with_cache_lock(cache_dir, LockMode::Exclusive, || {
        let path = cache_file_path(cache_dir, cache_key);
        let entry = read_cache_entry(&path)?.ok_or(CacheError::InvalidRunTransition(
            "run recovery entry is missing",
        ))?;
        validate_entry_key(cache_key, &entry)?;
        let mut entry = match entry {
            CacheEntry::Run(entry) => entry,
            other => {
                return Err(CacheError::UnexpectedKind {
                    expected: "run",
                    actual: other.kind_name(),
                });
            }
        };
        operation(&mut entry)?;
        let bytes = serde_json::to_vec_pretty(&CacheEntry::Run(entry)).map_err(CacheError::Json)?;
        persist_cache_file(cache_dir, &path, &bytes)?;
        let CacheEntry::Run(entry) = read_cache_entry(&path)?.ok_or(
            CacheError::InvalidRunTransition("run recovery entry disappeared after transition"),
        )?
        else {
            unreachable!("persisted run entry changed kind")
        };
        Ok(entry)
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

    validate_cache_key(hash_key)?;
    let result = with_cache_lock(cache_dir, LockMode::Exclusive, || {
        read_cache_entry(&cache_file_path(cache_dir, hash_key))
    });
    if let Err(error) = &result {
        tracing::debug!(
            cache_dir = %cache_dir.display(),
            cache_key = hash_key,
            error = %error,
            "cache lookup failed"
        );
    }
    result
}

/// Deletes a cache entry file `cache_dir/<hash_key>.json`.
#[cfg(test)]
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

#[cfg(test)]
pub type CacheFileEntries = Vec<(String, Result<CacheEntry, CacheError>)>;

/// Lists all cache entry files in `cache_dir`, returning `(hash_key, Result<CacheEntry, CacheError>)`.
#[cfg(test)]
pub fn list_all_cache_entries(cache_dir: &Path) -> Result<CacheFileEntries, CacheError> {
    if !cache_dir_exists(cache_dir)? {
        return Ok(Vec::new());
    }

    with_cache_lock(cache_dir, LockMode::Exclusive, || {
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
            let header: CacheSchemaHeader =
                serde_json::from_str(&content).map_err(|error| {
                    tracing::debug!(path = %cache_file.display(), error = %error, "failed to decode cache entry header");
                    CacheError::Json(error)
                })?;
            let expected_version = match header.kind.as_str() {
                "root" | "derived" => Some(crate::cache::CACHE_SCHEMA_VERSION),
                "run" => Some(crate::cache::RUN_CACHE_SCHEMA_VERSION),
                _ => None,
            };
            if expected_version.is_some() && header.version != expected_version {
                tracing::warn!(
                    path = %cache_file.display(),
                    kind = %header.kind,
                    version = ?header.version,
                    "discarding cache entry with unsupported schema"
                );
                fs::remove_file(cache_file).map_err(CacheError::Io)?;
                let cache_dir = cache_file
                    .parent()
                    .ok_or(CacheError::Platform("cache entry has no parent directory"))?;
                sync_cache_dir(cache_dir)?;
                return Ok(None);
            }
            serde_json::from_str(&content)
                .map(Some)
                .map_err(|error| {
                    tracing::debug!(path = %cache_file.display(), error = %error, "failed to decode current cache entry");
                    CacheError::Json(error)
                })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(CacheError::Io(err)),
    }
}

#[derive(serde::Deserialize)]
struct CacheSchemaHeader {
    kind: String,
    version: Option<u32>,
}
