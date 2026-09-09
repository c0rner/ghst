use crate::cache::error::CacheError;
use crate::cache::key::{
    cache_file_path, compute_cache_key, compute_run_cache_key, validate_cache_key,
};
use crate::cache::lock::{LockMode, cache_dir_exists, ensure_cache_dir, with_cache_lock};
#[cfg(test)]
use crate::cache::lock::{read_epoch, with_locked_file};
use crate::cache::types::{
    CACHE_SCHEMA_VERSION, CacheEntryDto, RUN_CACHE_SCHEMA_VERSION, Record, RecordWriteView,
    RunRecordWriteView,
};
#[cfg(test)]
use crate::cache::types::{ReplaceCacheEntry, SaveCacheEntry};
use crate::run::RunRecord;
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::path::Path;

pub enum CacheInspectionState {
    Current(Box<Record>),
    Invalid,
}

pub struct CacheInspection {
    pub label: String,
    pub cache_key: Option<String>,
    pub state: CacheInspectionState,
}

pub use crate::credential::store::DeleteBaseOutcome;

pub fn inspect_cache(cache_dir: &Path) -> Result<Vec<CacheInspection>, CacheError> {
    if !cache_dir_exists(cache_dir)? {
        return Ok(Vec::new());
    }
    with_cache_lock(cache_dir, LockMode::Exclusive, || {
        inspect_unlocked(cache_dir)
    })
}

pub(super) fn inspect_unlocked(cache_dir: &Path) -> Result<Vec<CacheInspection>, CacheError> {
    let mut entries = Vec::new();
    for item in fs::read_dir(cache_dir).map_err(|err| CacheError::io(cache_dir, err))? {
        let item = item.map_err(|err| CacheError::io(cache_dir, err))?;
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
            label,
            cache_key,
            state,
        });
    }
    entries.sort_by(|left, right| left.label.cmp(&right.label));
    Ok(entries)
}

/// Saves a `Record` to `cache_dir/<hash_key>.json`.
///
/// A compatible current entry is retained. An expired or same-kind
/// stale-provenance entry is atomically replaced. Malformed, inconsistent,
/// wrong-kind, and unsupported-schema entries fail closed and are retained.
#[cfg(test)]
pub fn save_cache_entry(
    cache_dir: &Path,
    hash_key: &str,
    entry: &Record,
) -> Result<SaveCacheEntry, CacheError> {
    ensure_cache_dir(cache_dir)?;
    validate_entry_key(hash_key, entry)?;
    let write_view = RecordWriteView::from(entry);
    let json_bytes = serde_json::to_vec_pretty(&write_view).map_err(CacheError::Json)?;

    with_cache_lock(cache_dir, LockMode::Exclusive, || {
        save_unlocked(cache_dir, hash_key, entry, &json_bytes)
    })
}

/// Replaces the exact scoped entry selected for renewal under the cache lock.
///
/// A compatible entry written by a concurrent renewal is retained instead. The
/// caller owns cleanup of either the displaced token or its unused candidate.
#[cfg(test)]
pub fn replace_cache_candidate(
    cache_dir: &Path,
    hash_key: &str,
    expected: &Record,
    candidate: &Record,
    epoch: u64,
    expected_base: (&str, &str),
    now: time::OffsetDateTime,
) -> Result<ReplaceCacheEntry, CacheError> {
    ensure_cache_dir(cache_dir)?;
    validate_entry_key(hash_key, expected)?;
    validate_entry_key(hash_key, candidate)?;
    if !matches!(expected, Record::Scoped(_)) || !matches!(candidate, Record::Scoped(_)) {
        return Err(CacheError::UnexpectedKind {
            expected: "scoped",
            actual: candidate.kind_name(),
        });
    }
    let write_view = RecordWriteView::from(candidate);
    let json_bytes = serde_json::to_vec_pretty(&write_view).map_err(CacheError::Json)?;
    with_locked_file(cache_dir, LockMode::Exclusive, |lock| {
        let actual = read_epoch(lock)?;
        if actual != epoch {
            return Err(CacheError::EpochChanged {
                expected: epoch,
                actual,
            });
        }
        let (base_key, generation) = expected_base;
        let base = read_cache_entry(&cache_file_path(cache_dir, base_key))?;
        if !matches!(base, Some(Record::Base(ref base)) if base.generation_fingerprint() == generation)
        {
            return Err(CacheError::BaseGenerationChanged);
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

#[cfg(test)]
fn save_unlocked(
    cache_dir: &Path,
    hash_key: &str,
    entry: &Record,
    json_bytes: &[u8],
) -> Result<SaveCacheEntry, CacheError> {
    let cache_file = cache_file_path(cache_dir, hash_key);
    if let Some(existing) = read_cache_entry(&cache_file)? {
        validate_entry_key(hash_key, &existing)?;
        if matches!(&existing, Record::Run(_)) {
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
    _cache_dir: &Path,
    cache_file: &Path,
    json_bytes: &[u8],
) -> Result<(), CacheError> {
    crate::fs::publish_replacement(cache_file, json_bytes).map_err(CacheError::from)
}

pub(super) fn validate_entry_key(hash_key: &str, entry: &Record) -> Result<(), CacheError> {
    let actual_key = match entry {
        Record::Base(_) | Record::Scoped(_) => {
            compute_cache_key(entry.profile(), entry.repo_scope())
        }
        Record::Run(entry) => compute_run_cache_key(&entry.run_id),
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

pub fn claim_abandoned_run(
    cache_dir: &Path,
    cache_key: &str,
    expected: &RunRecord,
) -> Result<RunRecord, CacheError> {
    update_run(cache_dir, cache_key, |entry| {
        entry.claim_abandoned(expected).map_err(CacheError::from)
    })
}

pub fn delete_run_after_cleanup(
    cache_dir: &Path,
    cache_key: &str,
    expected: &RunRecord,
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
            Record::Run(entry) => {
                entry
                    .validate_cleanup_deletion(expected)
                    .map_err(CacheError::from)?;
                fs::remove_file(&path).map_err(|err| CacheError::io(&path, err))?;
                crate::fs::sync_private_dir(cache_dir).map_err(CacheError::from)?;
                Ok(true)
            }
            other => Err(CacheError::UnexpectedKind {
                expected: "run",
                actual: other.kind_name(),
            }),
        }
    })
}

pub fn delete_base_if_generation(
    cache_dir: &Path,
    cache_key: &str,
    expected_generation: &str,
) -> Result<DeleteBaseOutcome, CacheError> {
    if !cache_dir_exists(cache_dir)? {
        return Ok(DeleteBaseOutcome::Missing);
    }
    validate_cache_key(cache_key)?;
    with_cache_lock(cache_dir, LockMode::Exclusive, || {
        let path = cache_file_path(cache_dir, cache_key);
        let Some(entry) = read_cache_entry(&path)? else {
            return Ok(DeleteBaseOutcome::Missing);
        };
        validate_entry_key(cache_key, &entry)?;
        match entry {
            Record::Base(entry) if entry.generation_fingerprint() == expected_generation => {
                fs::remove_file(&path).map_err(|err| CacheError::io(&path, err))?;
                crate::fs::sync_private_dir(cache_dir).map_err(CacheError::from)?;
                Ok(DeleteBaseOutcome::Deleted)
            }
            Record::Base(_) => Ok(DeleteBaseOutcome::Changed),
            other => Err(CacheError::UnexpectedKind {
                expected: "base",
                actual: other.kind_name(),
            }),
        }
    })
}

pub(super) fn update_run(
    cache_dir: &Path,
    cache_key: &str,
    operation: impl FnOnce(&mut RunRecord) -> Result<(), CacheError>,
) -> Result<RunRecord, CacheError> {
    ensure_cache_dir(cache_dir)?;
    validate_cache_key(cache_key)?;
    with_cache_lock(cache_dir, LockMode::Exclusive, || {
        let path = cache_file_path(cache_dir, cache_key);
        let entry = read_cache_entry(&path)?.ok_or(CacheError::InvalidRunTransition(
            "run recovery entry is missing",
        ))?;
        validate_entry_key(cache_key, &entry)?;
        let mut entry = match entry {
            Record::Run(entry) => entry,
            other => {
                return Err(CacheError::UnexpectedKind {
                    expected: "run",
                    actual: other.kind_name(),
                });
            }
        };
        operation(&mut entry)?;
        let write_view = RecordWriteView::Run(RunRecordWriteView::from(&entry));
        let bytes = serde_json::to_vec_pretty(&write_view).map_err(CacheError::Json)?;
        persist_cache_file(cache_dir, &path, &bytes)?;
        let Record::Run(entry) = read_cache_entry(&path)?.ok_or(
            CacheError::InvalidRunTransition("run recovery entry disappeared after transition"),
        )?
        else {
            unreachable!("persisted run entry changed kind")
        };
        Ok(entry)
    })
}

/// Loads a `Record` from `cache_dir/<hash_key>.json`.
pub fn load_cache_entry(cache_dir: &Path, hash_key: &str) -> Result<Option<Record>, CacheError> {
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
        match crate::fs::open_private_file(&cache_file) {
            Ok(_) => {
                fs::remove_file(&cache_file).map_err(|err| CacheError::io(&cache_file, err))?;
                crate::fs::sync_private_dir(cache_dir).map_err(CacheError::from)?;
                Ok(true)
            }
            Err(crate::fs::FsError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(false)
            }
            Err(err) => Err(CacheError::from(err)),
        }
    })
}

#[cfg(test)]
pub type CacheFileEntries = Vec<(String, Result<Record, CacheError>)>;

/// Lists all cache entry files in `cache_dir`, returning `(hash_key, Result<Record, CacheError>)`.
#[cfg(test)]
pub fn list_all_cache_entries(cache_dir: &Path) -> Result<CacheFileEntries, CacheError> {
    if !cache_dir_exists(cache_dir)? {
        return Ok(Vec::new());
    }

    with_cache_lock(cache_dir, LockMode::Exclusive, || {
        let mut entries = Vec::new();
        let read_dir = fs::read_dir(cache_dir).map_err(|err| CacheError::io(cache_dir, err))?;
        for entry in read_dir {
            let entry = entry.map_err(|err| CacheError::io(cache_dir, err))?;
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

pub(super) fn read_cache_entry(cache_file: &Path) -> Result<Option<Record>, CacheError> {
    let mut file = match crate::fs::open_private_file(cache_file) {
        Ok(file) => file,
        Err(crate::fs::FsError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(error) => return Err(CacheError::from(error)),
    };
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|err| CacheError::io(cache_file, err))?;
    let header: CacheSchemaHeader =
        serde_json::from_str(&content).map_err(|error| {
            tracing::debug!(path = %cache_file.display(), error = %error, "failed to decode cache entry header");
            CacheError::Json(error)
        })?;
    let expected_version = match header.kind.as_str() {
        "base" | "scoped" => Some(CACHE_SCHEMA_VERSION),
        "run" => Some(RUN_CACHE_SCHEMA_VERSION),
        _ => None,
    };
    if let Some(expected) = expected_version
        && header.version != Some(expected)
    {
        return Err(CacheError::UnsupportedSchema {
            kind: header.kind,
            version: header.version,
            expected,
        });
    }
    let dto: CacheEntryDto = serde_json::from_str(&content).map_err(|error| {
        tracing::debug!(path = %cache_file.display(), error = %error, "failed to decode current cache entry");
        CacheError::Json(error)
    })?;
    Ok(Some(Record::try_from(dto)?))
}

#[derive(serde::Deserialize)]
struct CacheSchemaHeader {
    kind: String,
    version: Option<u32>,
}
