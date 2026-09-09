use crate::cache::error::CacheError;
use crate::cache::key::{
    cache_file_path, compute_cache_key, compute_run_cache_key, validate_cache_key,
};
use crate::cache::lock::{
    LockMode, cache_dir_exists, ensure_cache_dir, increment_epoch, read_epoch, with_cache_lock,
    with_locked_file,
};
use crate::cache::run_storage;
use crate::cache::storage::{
    CacheInspectionState, claim_abandoned_run, delete_run_after_cleanup, inspect_cache,
    read_cache_entry, validate_entry_key,
};
use crate::cache::types::{
    BaseRecordWriteView, RecordWriteView, RunRecordWriteView, ScopedRecordWriteView,
};
use crate::credential::store::{
    DeleteBaseOutcome, IssuanceGuard, IssuanceGuardStore, ReadCredentials, ReplaceOutcome,
    SaveOutcome, SourceGuard, WriteCredentials,
};
use crate::credential::{BaseCredential, ScopedCredential};
use crate::run::RunRecord;
use crate::run::store::{PendingRunOutcome, PendingRunStore, RunLifecycleStore};
use crate::token::store::{
    BeginRevocation, DeleteInspectedRecord, DeleteOutcome, InspectRecords, InspectionState, Record,
    RecordInspection, RevocationBatch, RevocationSelection,
};
use std::path::Path;
use std::path::PathBuf;
use time::OffsetDateTime;

/// Concrete filesystem cache implementation of feature storage contracts.
pub struct CacheStore {
    path: PathBuf,
}

impl CacheStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub(crate) fn delete_exact_record_with_sync<F>(
        &self,
        slot_id: &str,
        expected: &Record,
        sync_fn: F,
    ) -> Result<DeleteOutcome<CacheError>, CacheError>
    where
        F: FnOnce(&Path) -> Result<(), crate::fs::FsError>,
    {
        if !cache_dir_exists(&self.path)? {
            return Ok(DeleteOutcome::Missing);
        }
        validate_cache_key(slot_id)?;
        with_cache_lock(&self.path, LockMode::Exclusive, || {
            let path = cache_file_path(&self.path, slot_id);
            let Some(entry) = read_cache_entry(&path)? else {
                return Ok(DeleteOutcome::Missing);
            };
            validate_entry_key(slot_id, &entry)?;
            if &entry != expected {
                return Ok(DeleteOutcome::Changed);
            }
            std::fs::remove_file(&path).map_err(|err| CacheError::io(&path, err))?;
            if let Err(err) = sync_fn(&self.path) {
                return Ok(DeleteOutcome::UnlinkedSyncFailed(CacheError::from(err)));
            }
            Ok(DeleteOutcome::Deleted)
        })
    }
}

impl ReadCredentials for CacheStore {
    type Error = CacheError;

    fn read_base(&self, profile: &str) -> Result<Option<BaseCredential>, Self::Error> {
        let key = compute_cache_key(profile, "all");
        let Some(entry) = crate::cache::storage::load_cache_entry(&self.path, &key)? else {
            return Ok(None);
        };
        crate::cache::storage::validate_entry_key(&key, &entry)?;
        match entry {
            Record::Base(b) => Ok(Some(b)),
            other => Err(CacheError::UnexpectedKind {
                expected: "base",
                actual: other.kind_name(),
            }),
        }
    }

    fn read_scoped(
        &self,
        profile: &str,
        repo_scope: &str,
    ) -> Result<Option<ScopedCredential>, Self::Error> {
        let key = compute_cache_key(profile, repo_scope);
        let Some(entry) = crate::cache::storage::load_cache_entry(&self.path, &key)? else {
            return Ok(None);
        };
        crate::cache::storage::validate_entry_key(&key, &entry)?;
        match entry {
            Record::Scoped(s) => Ok(Some(s)),
            other => Err(CacheError::UnexpectedKind {
                expected: "scoped",
                actual: other.kind_name(),
            }),
        }
    }
}

impl IssuanceGuardStore for CacheStore {
    type Error = CacheError;

    fn issuance_guard(&self) -> Result<IssuanceGuard, Self::Error> {
        crate::cache::lock::cache_epoch(&self.path).map(IssuanceGuard::new)
    }
}

impl WriteCredentials for CacheStore {
    type Error = CacheError;

    fn commit_base(
        &self,
        candidate: &BaseCredential,
        guard: IssuanceGuard,
    ) -> Result<SaveOutcome<BaseCredential>, Self::Error> {
        ensure_cache_dir(&self.path)?;
        let key = compute_cache_key(&candidate.profile, "all");
        let write_view = RecordWriteView::Base(BaseRecordWriteView::from(candidate));
        let json_bytes = serde_json::to_vec_pretty(&write_view).map_err(CacheError::Json)?;

        with_locked_file(&self.path, LockMode::Exclusive, |lock| {
            let actual = read_epoch(lock)?;
            if actual != guard.value() {
                return Ok(SaveOutcome::EpochChanged);
            }
            let cache_file = cache_file_path(&self.path, &key);
            if let Some(existing) = read_cache_entry(&cache_file)? {
                validate_entry_key(&key, &existing)?;
                match existing {
                    Record::Base(b) => {
                        if b.compatible_with(candidate, OffsetDateTime::now_utc()) {
                            return Ok(SaveOutcome::Retained(b));
                        }
                    }
                    other => {
                        return Err(CacheError::UnexpectedKind {
                            expected: "base",
                            actual: other.kind_name(),
                        });
                    }
                }
            }
            crate::fs::publish_replacement(&cache_file, &json_bytes).map_err(CacheError::from)?;
            Ok(SaveOutcome::Saved)
        })
    }

    fn commit_scoped(
        &self,
        candidate: &ScopedCredential,
        guard: IssuanceGuard,
        source_guard: &SourceGuard<'_>,
    ) -> Result<SaveOutcome<ScopedCredential>, Self::Error> {
        ensure_cache_dir(&self.path)?;
        let key = compute_cache_key(&candidate.profile, &candidate.repo_scope);
        let write_view = RecordWriteView::Scoped(ScopedRecordWriteView::from(candidate));
        let json_bytes = serde_json::to_vec_pretty(&write_view).map_err(CacheError::Json)?;

        with_locked_file(&self.path, LockMode::Exclusive, |lock| {
            let actual = read_epoch(lock)?;
            if actual != guard.value() {
                return Ok(SaveOutcome::EpochChanged);
            }
            if !validate_source_base(&self.path, source_guard)? {
                return Ok(SaveOutcome::BaseGenerationChanged);
            }
            let cache_file = cache_file_path(&self.path, &key);
            if let Some(existing) = read_cache_entry(&cache_file)? {
                validate_entry_key(&key, &existing)?;
                match existing {
                    Record::Scoped(s) => {
                        if s.compatible_with(candidate, OffsetDateTime::now_utc()) {
                            return Ok(SaveOutcome::Retained(s));
                        }
                    }
                    other => {
                        return Err(CacheError::UnexpectedKind {
                            expected: "scoped",
                            actual: other.kind_name(),
                        });
                    }
                }
            }
            crate::fs::publish_replacement(&cache_file, &json_bytes).map_err(CacheError::from)?;
            Ok(SaveOutcome::Saved)
        })
    }

    fn renew_scoped(
        &self,
        expected: &ScopedCredential,
        candidate: &ScopedCredential,
        guard: IssuanceGuard,
        source_guard: &SourceGuard<'_>,
        now: OffsetDateTime,
    ) -> Result<ReplaceOutcome<ScopedCredential>, Self::Error> {
        ensure_cache_dir(&self.path)?;
        let key = compute_cache_key(&candidate.profile, &candidate.repo_scope);
        let write_view = RecordWriteView::Scoped(ScopedRecordWriteView::from(candidate));
        let json_bytes = serde_json::to_vec_pretty(&write_view).map_err(CacheError::Json)?;

        with_locked_file(&self.path, LockMode::Exclusive, |lock| {
            let actual = read_epoch(lock)?;
            if actual != guard.value() {
                return Ok(ReplaceOutcome::EpochChanged);
            }
            if !validate_source_base(&self.path, source_guard)? {
                return Ok(ReplaceOutcome::BaseGenerationChanged);
            }

            let cache_file = cache_file_path(&self.path, &key);
            let Some(current) = read_cache_entry(&cache_file)? else {
                return Ok(ReplaceOutcome::RenewalEntryChanged);
            };
            validate_entry_key(&key, &current)?;
            let Record::Scoped(current_scoped) = current else {
                return Err(CacheError::UnexpectedKind {
                    expected: "scoped",
                    actual: current.kind_name(),
                });
            };
            if &current_scoped == expected {
                crate::fs::publish_replacement(&cache_file, &json_bytes)
                    .map_err(CacheError::from)?;
                return Ok(ReplaceOutcome::Replaced(current_scoped));
            }
            if current_scoped.compatible_with(candidate, now) {
                return Ok(ReplaceOutcome::Retained(current_scoped));
            }
            Ok(ReplaceOutcome::RenewalEntryChanged)
        })
    }

    fn delete_base_if_generation(
        &self,
        profile: &str,
        expected_generation: &str,
    ) -> Result<DeleteBaseOutcome, Self::Error> {
        let key = compute_cache_key(profile, "all");
        crate::cache::storage::delete_base_if_generation(&self.path, &key, expected_generation)
    }
}

fn validate_source_base(
    cache_dir: &Path,
    source_guard: &SourceGuard<'_>,
) -> Result<bool, CacheError> {
    let base_key = compute_cache_key(source_guard.source_profile, "all");
    let base = read_cache_entry(&cache_file_path(cache_dir, &base_key))?;
    let Some(base_entry) = base else {
        return Ok(false);
    };
    crate::cache::storage::validate_entry_key(&base_key, &base_entry)?;
    let Record::Base(ref base) = base_entry else {
        return Err(CacheError::UnexpectedKind {
            expected: "base",
            actual: base_entry.kind_name(),
        });
    };
    Ok(base.generation_fingerprint() == source_guard.expected_generation)
}

impl PendingRunStore for CacheStore {
    type Error = CacheError;

    fn commit_pending(
        &self,
        candidate: &RunRecord,
        guard: IssuanceGuard,
        source_guard: &SourceGuard<'_>,
    ) -> Result<PendingRunOutcome, Self::Error> {
        ensure_cache_dir(&self.path)?;
        let key = compute_run_cache_key(&candidate.run_id);
        let write_view = RecordWriteView::Run(RunRecordWriteView::from(candidate));
        let json_bytes = serde_json::to_vec_pretty(&write_view).map_err(CacheError::Json)?;

        with_locked_file(&self.path, LockMode::Exclusive, |lock| {
            let actual = read_epoch(lock)?;
            if actual != guard.value() {
                return Ok(PendingRunOutcome::EpochChanged);
            }
            if !validate_source_base(&self.path, source_guard)? {
                return Ok(PendingRunOutcome::BaseGenerationChanged);
            }
            let cache_file = cache_file_path(&self.path, &key);
            if let Some(existing) = read_cache_entry(&cache_file)? {
                validate_entry_key(&key, &existing)?;
                return Err(CacheError::RunCollision(key));
            }
            crate::fs::publish_replacement(&cache_file, &json_bytes).map_err(CacheError::from)?;
            Ok(PendingRunOutcome::Saved)
        })
    }
}

impl RunLifecycleStore for CacheStore {
    type Error = CacheError;

    fn activate(
        &self,
        run_id: &str,
        wrapper_pid: u32,
        child_pid: u32,
    ) -> Result<RunRecord, Self::Error> {
        let key = compute_run_cache_key(run_id);
        run_storage::activate(&self.path, &key, run_id, wrapper_pid, child_pid)
    }

    fn abort(
        &self,
        run_id: &str,
        wrapper_pid: u32,
        child_pid: Option<u32>,
    ) -> Result<RunRecord, Self::Error> {
        let key = compute_run_cache_key(run_id);
        run_storage::abort(&self.path, &key, run_id, wrapper_pid, child_pid)
    }

    fn finish(
        &self,
        run_id: &str,
        wrapper_pid: u32,
        child_pid: u32,
    ) -> Result<RunRecord, Self::Error> {
        let key = compute_run_cache_key(run_id);
        run_storage::finish(&self.path, &key, run_id, wrapper_pid, child_pid)
    }

    fn claim_abandoned(&self, expected: &RunRecord) -> Result<RunRecord, Self::Error> {
        let key = compute_run_cache_key(&expected.run_id);
        claim_abandoned_run(&self.path, &key, expected)
    }

    fn delete_cleanup_pending(&self, expected: &RunRecord) -> Result<bool, Self::Error> {
        let key = compute_run_cache_key(&expected.run_id);
        delete_run_after_cleanup(&self.path, &key, expected)
    }
}

impl InspectRecords for CacheStore {
    type Error = CacheError;

    fn inspect_records(&self) -> Result<Vec<RecordInspection>, Self::Error> {
        let inspections = inspect_cache(&self.path)?;
        Ok(inspections
            .into_iter()
            .map(|inspection| RecordInspection {
                label: inspection.label,
                slot_id: inspection.cache_key,
                state: match inspection.state {
                    CacheInspectionState::Current(entry) => InspectionState::Current(entry),
                    CacheInspectionState::Invalid => InspectionState::Invalid,
                },
            })
            .collect())
    }
}

impl DeleteInspectedRecord for CacheStore {
    type Error = CacheError;

    fn delete_exact_record(
        &self,
        slot_id: &str,
        expected: &Record,
    ) -> Result<DeleteOutcome<Self::Error>, Self::Error> {
        self.delete_exact_record_with_sync(slot_id, expected, crate::fs::sync_private_dir)
    }
}

impl BeginRevocation for CacheStore {
    type Error = CacheError;

    fn begin_revocation(
        &self,
        selection: RevocationSelection<'_>,
    ) -> Result<RevocationBatch, Self::Error> {
        with_locked_file(&self.path, LockMode::Exclusive, |lock| {
            increment_epoch(lock)?;
            let entries = crate::cache::storage::inspect_unlocked(&self.path)?;
            let selected_inspections = match selection {
                RevocationSelection::All => entries,
                RevocationSelection::One(target_id) => {
                    let matching: Vec<_> = entries
                        .into_iter()
                        .filter(|inspection| {
                            inspection.cache_key.as_deref().is_some_and(|key| {
                                key.get(..target_id.len())
                                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(target_id))
                            })
                        })
                        .collect();
                    match matching.len() {
                        0 => return Ok(RevocationBatch::NotFound),
                        1 => matching,
                        _ => return Ok(RevocationBatch::Ambiguous),
                    }
                }
            };
            let snapshots = selected_inspections
                .into_iter()
                .map(|inspection| RecordInspection {
                    label: inspection.label,
                    slot_id: inspection.cache_key,
                    state: match inspection.state {
                        CacheInspectionState::Current(entry) => InspectionState::Current(entry),
                        CacheInspectionState::Invalid => InspectionState::Invalid,
                    },
                })
                .collect();
            Ok(RevocationBatch::Selected(snapshots))
        })
    }
}
