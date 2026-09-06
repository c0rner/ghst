use super::{storage, types};
use crate::credential::store::{
    self, Inspect, Inspection, InspectionState, IssuanceGuard, Issue, Login, Remove, Revocation,
    Revoke, StoreError,
};
use crate::credential::store::{ReplaceStoredCredential, SaveStoredCredential};
use crate::credential::stored::{StoredCredential, StoredRun};
use crate::run::{lifecycle::RunOwner, store::RunStore};
use std::path::Path;
use time::OffsetDateTime;

pub struct FsCredentialStore<'a> {
    directory: &'a Path,
}
impl<'a> FsCredentialStore<'a> {
    pub const fn new(directory: &'a Path) -> Self {
        Self { directory }
    }
}
impl Inspect for FsCredentialStore<'_> {
    fn load(&self, key: &str) -> Result<Option<StoredCredential>, StoreError> {
        storage::load_cache_entry(self.directory, key)?
            .map(TryInto::try_into)
            .transpose()
    }
    fn inspect(&self) -> Result<Vec<Inspection>, StoreError> {
        storage::inspect_cache(self.directory)?
            .into_iter()
            .map(inspection)
            .collect()
    }
}
fn inspection(value: storage::CacheInspection) -> Result<Inspection, StoreError> {
    Ok(Inspection {
        label: value.label,
        cache_key: value.cache_key,
        state: match value.state {
            storage::CacheInspectionState::Current(entry) => {
                InspectionState::Current(Box::new((*entry).try_into()?))
            }
            storage::CacheInspectionState::Invalid => InspectionState::Invalid,
        },
    })
}
impl Issue for FsCredentialStore<'_> {
    fn epoch(&self) -> Result<u64, StoreError> {
        super::cache_epoch(self.directory)
    }
    fn commit(
        &self,
        key: &str,
        candidate: &StoredCredential,
        guard: IssuanceGuard<'_>,
    ) -> Result<SaveStoredCredential, StoreError> {
        match storage::save_cache_candidate(
            self.directory,
            key,
            &candidate.into(),
            guard.epoch,
            Some((guard.source.key, guard.source.generation)),
        )? {
            types::SaveCacheEntry::Saved => Ok(SaveStoredCredential::Saved),
            types::SaveCacheEntry::Retained(v) => {
                Ok(SaveStoredCredential::Retained(Box::new((*v).try_into()?)))
            }
        }
    }
    fn renew(
        &self,
        key: &str,
        expected: &StoredCredential,
        candidate: &StoredCredential,
        guard: IssuanceGuard<'_>,
        now: OffsetDateTime,
    ) -> Result<ReplaceStoredCredential, StoreError> {
        let source = guard.source;
        match storage::replace_cache_candidate(
            self.directory,
            key,
            &expected.into(),
            &candidate.into(),
            guard.epoch,
            (source.key, source.generation),
            now,
        )? {
            types::ReplaceCacheEntry::Replaced(v) => Ok(ReplaceStoredCredential::Replaced(
                Box::new((*v).try_into()?),
            )),
            types::ReplaceCacheEntry::Retained(v) => Ok(ReplaceStoredCredential::Retained(
                Box::new((*v).try_into()?),
            )),
        }
    }
}
impl Remove for FsCredentialStore<'_> {
    fn delete_unchanged(&self, key: &str, expected: &StoredCredential) -> Result<bool, StoreError> {
        storage::delete_entry_if_unchanged(self.directory, key, &expected.into())
    }
    fn delete_base_generation(
        &self,
        key: &str,
        generation: &str,
    ) -> Result<store::DeleteBaseOutcome, StoreError> {
        storage::delete_base_if_generation(self.directory, key, generation).map(|outcome| {
            match outcome {
                storage::DeleteBaseOutcome::Deleted => store::DeleteBaseOutcome::Deleted,
                storage::DeleteBaseOutcome::Missing => store::DeleteBaseOutcome::Missing,
                storage::DeleteBaseOutcome::Changed => store::DeleteBaseOutcome::Changed,
            }
        })
    }
}
impl RunStore for FsCredentialStore<'_> {
    fn activate(
        &self,
        key: &str,
        owner: RunOwner<'_>,
        child_pid: u32,
    ) -> Result<StoredRun, StoreError> {
        super::run_storage::activate(
            self.directory,
            key,
            owner.run_id,
            owner.wrapper_pid,
            child_pid,
        )?
        .try_into()
    }
    fn abort(
        &self,
        key: &str,
        owner: RunOwner<'_>,
        child_pid: Option<u32>,
    ) -> Result<StoredRun, StoreError> {
        super::run_storage::abort(
            self.directory,
            key,
            owner.run_id,
            owner.wrapper_pid,
            child_pid,
        )?
        .try_into()
    }
    fn finish(
        &self,
        key: &str,
        owner: RunOwner<'_>,
        child_pid: u32,
    ) -> Result<StoredRun, StoreError> {
        super::run_storage::finish(
            self.directory,
            key,
            owner.run_id,
            owner.wrapper_pid,
            child_pid,
        )?
        .try_into()
    }
    fn claim_abandoned(&self, key: &str, expected: &StoredRun) -> Result<StoredRun, StoreError> {
        storage::claim_abandoned_run(self.directory, key, &expected.into())?.try_into()
    }
    fn delete_cleaned(&self, key: &str, expected: &StoredRun) -> Result<bool, StoreError> {
        storage::delete_run_after_cleanup(self.directory, key, &expected.into())
    }
}
impl Revoke for FsCredentialStore<'_> {
    fn revoke<R: Revocation>(
        &self,
        selected_id: Option<&str>,
        policy: &mut R,
    ) -> Result<usize, StoreError> {
        storage::revoke_transaction(self.directory, |transaction| {
            let selected: Vec<_> = transaction
                .entries()
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| {
                    selected_id
                        .is_none_or(|id| {
                            entry.cache_key.as_deref().is_some_and(|key| {
                                key.get(..id.len())
                                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(id))
                            })
                        })
                        .then_some(index)
                })
                .collect();
            let count = selected.len();
            if selected_id.is_some() && count != 1 {
                return Ok(count);
            }
            for index in selected {
                let view = inspection(transaction.take_inspection(index))?;
                if policy.should_delete(&view) {
                    policy.deleted(&view.label, transaction.delete(index));
                }
            }
            Ok(count)
        })?
    }
}
impl Login for FsCredentialStore<'_> {
    fn commit_login(
        &self,
        key: &str,
        candidate: &crate::credential::stored::StoredBase,
        epoch: u64,
    ) -> Result<SaveStoredCredential, StoreError> {
        let candidate = types::CacheEntry::Base(candidate.into());
        match storage::save_cache_candidate(self.directory, key, &candidate, epoch, None)? {
            types::SaveCacheEntry::Saved => Ok(SaveStoredCredential::Saved),
            types::SaveCacheEntry::Retained(v) => {
                Ok(SaveStoredCredential::Retained(Box::new((*v).try_into()?)))
            }
        }
    }
}
