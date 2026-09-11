use crate::credential::TokenExpiry;
use crate::profile::NamedAppRegistration;
use crate::run::cleanup::{
    CleanupAttempt, CleanupFailure, CleanupOutcome, CleanupReport, cleanup_marked_entry,
};
use crate::run::process::{LivenessOutcome, ProcessLiveness};
use crate::run::store::RunLifecycleStore;
use crate::run::{RunRecord, RunState};
use crate::token::RevokeTokenClient;
use crate::token::store::{
    DeleteInspectedRecord, DeleteOutcome, InspectRecords, InspectionState, Record,
};
use time::OffsetDateTime;

/// Prunes expired and abandoned cache entries from persistent storage.
pub fn prune<C, S, L, E>(
    client: &C,
    apps: &[NamedAppRegistration<'_>],
    store: &S,
    liveness: &L,
    now: OffsetDateTime,
) -> Result<CleanupReport<E>, E>
where
    C: RevokeTokenClient,
    S: InspectRecords<Error = E> + DeleteInspectedRecord<Error = E> + RunLifecycleStore<Error = E>,
    L: ProcessLiveness,
    E: std::error::Error + 'static,
{
    let mut report = CleanupReport::default();
    let inspections = store.inspect_records()?;
    tracing::debug!(
        entries = inspections.len(),
        "inspecting cache entries for pruning"
    );
    for inspection in inspections {
        let label = inspection.label;
        let attempt = match (inspection.slot_id, inspection.state) {
            (None, _) => {
                tracing::debug!(
                    entry = label,
                    "retaining cache entry with an invalid file name"
                );
                Err(CleanupFailure::InvalidEntry { entry: label })
            }
            (Some(_), InspectionState::Invalid) => {
                tracing::debug!(
                    entry = label,
                    "retaining invalid cache entry for manual inspection"
                );
                Err(CleanupFailure::InvalidEntry { entry: label })
            }
            (Some(slot_id), InspectionState::Current(entry)) if expiry(&entry).value() <= now => {
                delete_expired_entry(store, &slot_id, &label, &entry)
            }
            (Some(_slot_id), InspectionState::Current(entry)) => {
                cleanup_unexpired_entry(client, apps, store, liveness, &label, *entry)
            }
        };
        report.record(attempt);
    }
    Ok(report)
}

fn delete_expired_entry<S, E>(
    store: &S,
    slot_id: &str,
    label: &str,
    entry: &Record,
) -> CleanupAttempt<E>
where
    S: DeleteInspectedRecord<Error = E>,
    E: std::fmt::Display,
{
    tracing::debug!(
        entry = label,
        kind = entry.kind_name(),
        "deleting expired cache entry"
    );
    match store.delete_exact_record(slot_id, entry) {
        Ok(DeleteOutcome::Deleted) => {
            tracing::debug!(entry = label, "deleted expired cache entry");
            Ok(CleanupOutcome::ExpiredDeleted)
        }
        Ok(DeleteOutcome::Missing | DeleteOutcome::Changed) => {
            tracing::debug!(
                entry = label,
                "expired cache entry changed or disappeared before deletion"
            );
            Err(CleanupFailure::InvalidEntry {
                entry: label.to_owned(),
            })
        }
        Ok(DeleteOutcome::UnlinkedSyncFailed(source)) => {
            tracing::debug!(entry = label, error = %source, "directory sync failed after deleting expired cache entry");
            Err(CleanupFailure::DirectorySyncFailed {
                entry: label.to_owned(),
                source,
            })
        }
        Err(source) => {
            tracing::debug!(entry = label, error = %source, "failed to delete expired cache entry");
            Err(CleanupFailure::CacheDeletion {
                entry: label.to_owned(),
                source,
            })
        }
    }
}

fn cleanup_unexpired_entry<C, S, L, E>(
    client: &C,
    apps: &[NamedAppRegistration<'_>],
    store: &S,
    liveness: &L,
    label: &str,
    entry: Record,
) -> CleanupAttempt<E>
where
    C: RevokeTokenClient,
    S: RunLifecycleStore<Error = E>,
    L: ProcessLiveness,
    E: std::fmt::Display,
{
    match entry {
        Record::Base(_) | Record::Scoped(_) => Ok(CleanupOutcome::NoAction),
        Record::Run(entry) => cleanup_pruned_run(client, apps, store, liveness, label, &entry),
    }
}

fn cleanup_pruned_run<C, S, L, E>(
    client: &C,
    apps: &[NamedAppRegistration<'_>],
    store: &S,
    liveness: &L,
    label: &str,
    entry: &RunRecord,
) -> CleanupAttempt<E>
where
    C: RevokeTokenClient,
    S: RunLifecycleStore<Error = E>,
    L: ProcessLiveness,
    E: std::fmt::Display,
{
    match entry.state {
        RunState::CleanupPending => cleanup_marked_entry(client, apps, label, entry, store),
        RunState::Pending | RunState::Running => {
            let wrapper_dead = liveness.check_liveness(entry.wrapper_pid) == LivenessOutcome::Dead;
            let child_dead = entry
                .child_pid
                .is_none_or(|pid| liveness.check_liveness(pid) == LivenessOutcome::Dead);
            if !(wrapper_dead && child_dead) {
                tracing::debug!(
                    entry = label,
                    wrapper_pid = entry.wrapper_pid,
                    child_pid = ?entry.child_pid,
                    "skipping active run during pruning"
                );
                return Ok(CleanupOutcome::ActiveRunSkipped);
            }
            tracing::debug!(entry = label, "claiming abandoned run for cleanup");
            match store.claim_abandoned(entry) {
                Ok(claimed) => cleanup_marked_entry(client, apps, label, &claimed, store),
                Err(source) => {
                    tracing::debug!(entry = label, error = %source, "failed to claim abandoned run for cleanup");
                    Err(CleanupFailure::Ownership {
                        entry: label.to_owned(),
                        source,
                    })
                }
            }
        }
    }
}

const fn expiry(entry: &Record) -> TokenExpiry {
    entry.expires_at()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{compute_run_cache_key, load_cache_entry, write_test_entry};
    use crate::credential::{TokenExpiry, authority_fingerprint};
    use crate::profile::{AppAuthority, AppRegistration};
    use crate::run::{RunRecord, RunState};
    use crate::token::RemoteError;
    use std::cell::{Cell, RefCell};
    use time::Duration;

    struct MockClient {
        revoked: RefCell<Vec<String>>,
        fail: Cell<bool>,
    }

    impl RevokeTokenClient for MockClient {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            access_token: &str,
        ) -> Result<(), RemoteError> {
            self.revoked.borrow_mut().push(access_token.to_owned());
            if self.fail.get() {
                Err(RemoteError::Http {
                    status: 500,
                    message: "failure".into(),
                })
            } else {
                Ok(())
            }
        }
    }

    fn sample_apps() -> Vec<NamedAppRegistration<'static>> {
        vec![NamedAppRegistration {
            profile_name: "developer",
            app: AppRegistration {
                authority: AppAuthority {
                    account: "acme",
                    client_id: "id",
                },
                client_secret: Some("secret"),
            },
        }]
    }

    fn run_entry(
        run_id: &str,
        state: RunState,
        wrapper_pid: u32,
        child_pid: Option<u32>,
        expiry: OffsetDateTime,
    ) -> Record {
        Record::Run(RunRecord {
            run_id: run_id.into(),
            state,
            wrapper_pid,
            child_pid,
            command: "true".into(),
            profile: "reader".into(),
            source_profile: "developer".into(),
            source_authority_fingerprint: authority_fingerprint("id", "acme"),
            github_user: "octocat".into(),
            repo_scope: "acme/api".into(),
            expires_at: TokenExpiry::new(expiry),
            access_token: format!("token-{run_id}").into(),
        })
    }

    struct FakeLiveness {
        alive_pids: std::collections::HashSet<u32>,
    }

    impl FakeLiveness {
        fn new(alive_pids: impl IntoIterator<Item = u32>) -> Self {
            Self {
                alive_pids: alive_pids.into_iter().collect(),
            }
        }
    }

    impl ProcessLiveness for FakeLiveness {
        fn check_liveness(&self, pid: u32) -> LivenessOutcome {
            if self.alive_pids.contains(&pid) {
                LivenessOutcome::AliveOrUnknown
            } else {
                LivenessOutcome::Dead
            }
        }
    }

    fn client() -> MockClient {
        MockClient {
            revoked: RefCell::new(Vec::new()),
            fail: Cell::new(false),
        }
    }

    fn write_run(
        cache_dir: &std::path::Path,
        id: &str,
        state: RunState,
        wrapper_pid: u32,
        child_pid: Option<u32>,
        expiry: OffsetDateTime,
    ) {
        write_test_entry(
            cache_dir,
            &compute_run_cache_key(id),
            &run_entry(id, state, wrapper_pid, child_pid, expiry),
        )
        .unwrap();
    }

    #[test]
    fn prune_skips_active_runs_and_revokes_abandoned_runs() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        let exp = now + Duration::hours(1);

        // 1. Wrapper is alive (child dead) -> skipped
        write_run(
            &cache_dir,
            "wrapper-alive",
            RunState::Running,
            10,
            Some(11),
            exp,
        );

        // 2. Child is alive (wrapper dead) -> skipped
        write_run(
            &cache_dir,
            "child-alive",
            RunState::Running,
            20,
            Some(21),
            exp,
        );

        // 3. Both dead (Running) -> claimed and revoked
        write_run(
            &cache_dir,
            "abandoned-running",
            RunState::Running,
            30,
            Some(31),
            exp,
        );

        // 4. Wrapper dead, no child (Pending) -> claimed and revoked
        write_run(
            &cache_dir,
            "abandoned-pending",
            RunState::Pending,
            40,
            None,
            exp,
        );

        // 5. CleanupPending -> retried immediately even though PIDs are marked alive
        write_run(
            &cache_dir,
            "cleanup-pending",
            RunState::CleanupPending,
            50,
            Some(51),
            exp,
        );

        let client = client();
        let store = crate::cache::CacheStore::new(&cache_dir);
        let apps = sample_apps();
        // PIDs 10, 21, 50, 51 are AliveOrUnknown. 11, 20, 30, 31, 40 are Dead.
        let liveness = FakeLiveness::new([10, 21, 50, 51]);
        let report = prune(&client, &apps, &store, &liveness, now).unwrap();

        assert_eq!(report.active_runs_skipped, 2);
        assert_eq!(report.revoked_runs, 3);
        assert!(report.is_complete());

        let mut revoked = client.revoked.borrow().clone();
        revoked.sort();
        assert_eq!(
            revoked,
            vec![
                "token-abandoned-pending",
                "token-abandoned-running",
                "token-cleanup-pending",
            ]
        );

        // Skipped runs remain in cache
        assert!(
            load_cache_entry(&cache_dir, &compute_run_cache_key("wrapper-alive"))
                .unwrap()
                .is_some()
        );
        assert!(
            load_cache_entry(&cache_dir, &compute_run_cache_key("child-alive"))
                .unwrap()
                .is_some()
        );

        // Revoked and cleaned-up runs are deleted from cache
        assert!(
            load_cache_entry(&cache_dir, &compute_run_cache_key("abandoned-running"))
                .unwrap()
                .is_none()
        );
        assert!(
            load_cache_entry(&cache_dir, &compute_run_cache_key("abandoned-pending"))
                .unwrap()
                .is_none()
        );
        assert!(
            load_cache_entry(&cache_dir, &compute_run_cache_key("cleanup-pending"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn prune_retains_claimed_abandoned_run_when_remote_revocation_fails() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        let key = compute_run_cache_key("abandoned");
        write_test_entry(
            &cache_dir,
            &key,
            &run_entry(
                "abandoned",
                RunState::Running,
                100,
                Some(101),
                now + Duration::hours(1),
            ),
        )
        .unwrap();
        let client = client();
        client.fail.set(true);
        let store = crate::cache::CacheStore::new(&cache_dir);
        let apps = sample_apps();
        let liveness = FakeLiveness::new([]);
        let report = prune(&client, &apps, &store, &liveness, now).unwrap();
        assert_eq!(report.retained_entries, 1);
        assert_eq!(report.failures.len(), 1);
        let Some(Record::Run(retained)) = load_cache_entry(&cache_dir, &key).unwrap() else {
            panic!("expected run record");
        };
        assert_eq!(retained.state, RunState::CleanupPending);
    }

    #[test]
    fn prune_does_not_revoke_with_mismatched_authority() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        let key = compute_run_cache_key("abandoned");
        let mut entry = run_entry(
            "abandoned",
            RunState::Running,
            100,
            Some(101),
            now + Duration::hours(1),
        );
        let Record::Run(ref mut run) = entry else {
            panic!("expected run");
        };
        run.source_authority_fingerprint = authority_fingerprint("wrong-id", "acme");
        write_test_entry(&cache_dir, &key, &entry).unwrap();

        let client = client();
        let store = crate::cache::CacheStore::new(&cache_dir);
        let apps = sample_apps();
        let liveness = FakeLiveness::new([]);
        let report = prune(&client, &apps, &store, &liveness, now).unwrap();
        assert_eq!(report.retained_entries, 1);
        assert!(client.revoked.borrow().is_empty());
        let Some(Record::Run(retained)) = load_cache_entry(&cache_dir, &key).unwrap() else {
            panic!("expected run record");
        };
        assert_eq!(retained.state, RunState::CleanupPending);
    }

    #[test]
    fn prune_deletes_expired_runs_without_remote_revocation() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        let key = compute_run_cache_key("expired");
        write_test_entry(
            &cache_dir,
            &key,
            &run_entry(
                "expired",
                RunState::Running,
                100,
                Some(101),
                now - Duration::minutes(1),
            ),
        )
        .unwrap();

        let client = client();
        let store = crate::cache::CacheStore::new(&cache_dir);
        let apps = sample_apps();
        let liveness = FakeLiveness::new([100, 101]);
        let report = prune(&client, &apps, &store, &liveness, now).unwrap();
        assert_eq!(report.expired_deletions, 1);
        assert!(report.is_complete());
        assert!(client.revoked.borrow().is_empty());
        assert!(load_cache_entry(&cache_dir, &key).unwrap().is_none());
    }

    /// A store that removes the file on `delete_exact_record` but then returns
    /// `UnlinkedSyncFailed`, simulating an fsync failure after the unlink.
    struct PostUnlinkSyncFailingStore {
        inner: crate::cache::CacheStore,
        cache_dir: std::path::PathBuf,
    }

    impl InspectRecords for PostUnlinkSyncFailingStore {
        type Error = crate::cache::CacheError;

        fn inspect_records(
            &self,
        ) -> Result<Vec<crate::token::store::RecordInspection>, Self::Error> {
            self.inner.inspect_records()
        }
    }

    impl RunLifecycleStore for PostUnlinkSyncFailingStore {
        type Error = crate::cache::CacheError;

        fn activate(&self, _: &str, _: u32, _: u32) -> Result<RunRecord, Self::Error> {
            unreachable!()
        }
        fn abort(&self, _: &str, _: u32, _: Option<u32>) -> Result<RunRecord, Self::Error> {
            unreachable!()
        }
        fn finish(&self, _: &str, _: u32, _: u32) -> Result<RunRecord, Self::Error> {
            unreachable!()
        }
        fn claim_abandoned(&self, _: &RunRecord) -> Result<RunRecord, Self::Error> {
            unreachable!()
        }
        fn delete_cleanup_pending(&self, _: &RunRecord) -> Result<bool, Self::Error> {
            unreachable!()
        }
    }

    impl DeleteInspectedRecord for PostUnlinkSyncFailingStore {
        type Error = crate::cache::CacheError;

        fn delete_exact_record(
            &self,
            slot_id: &str,
            _expected: &Record,
        ) -> Result<DeleteOutcome<Self::Error>, Self::Error> {
            let path = self.cache_dir.join(format!("{slot_id}.json"));
            std::fs::remove_file(&path).map_err(|err| crate::cache::CacheError::io(&path, err))?;
            Ok(DeleteOutcome::UnlinkedSyncFailed(
                crate::cache::CacheError::io(
                    &self.cache_dir,
                    std::io::Error::other("simulated sync failure"),
                ),
            ))
        }
    }

    #[test]
    fn prune_reports_directory_sync_failure_without_retaining() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        let key = compute_run_cache_key("expired");
        write_test_entry(
            &cache_dir,
            &key,
            &run_entry(
                "expired",
                RunState::CleanupPending,
                i32::MAX as u32,
                None,
                now - Duration::seconds(1),
            ),
        )
        .unwrap();

        let store = PostUnlinkSyncFailingStore {
            inner: crate::cache::CacheStore::new(&cache_dir),
            cache_dir: cache_dir.clone(),
        };
        let client = client();
        let apps = sample_apps();
        let liveness = FakeLiveness::new([]);
        let report = prune(&client, &apps, &store, &liveness, now).unwrap();

        assert_eq!(report.expired_deletions, 0);
        assert_eq!(
            report.retained_entries, 0,
            "file was unlinked; must not be counted as retained"
        );
        assert_eq!(report.failures.len(), 1);
        assert!(
            matches!(
                report.failures.as_slice(),
                [CleanupFailure::DirectorySyncFailed { .. }]
            ),
            "expected DirectorySyncFailed failure"
        );
        assert!(!report.is_complete());
        assert!(load_cache_entry(&cache_dir, &key).unwrap().is_none());
    }
}
