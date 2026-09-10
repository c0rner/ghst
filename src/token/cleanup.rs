use crate::config::{AppProfile, Config};
use crate::credential::TokenExpiry;
use crate::run::store::RunLifecycleStore;
use crate::run::{RunRecord, RunState};
use crate::token::store::{
    DeleteInspectedRecord, DeleteOutcome, InspectRecords, InspectionState, Record,
};
use crate::token::{RemoteError, RevokeTokenClient};
use time::OffsetDateTime;

pub enum CleanupFailure<E> {
    InvalidEntry { entry: String },
    Configuration { entry: String },
    ClientSecretUnavailable { entry: String },
    Ownership { entry: String, source: E },
    GitHubRevocation { entry: String, source: RemoteError },
    CacheDeletion { entry: String, source: E },
    DirectorySyncFailed { entry: String, source: E },
}

enum CleanupOutcome {
    NoAction,
    ExpiredDeleted,
    RunRevoked,
    ActiveRunSkipped,
}

type CleanupAttempt<E> = Result<CleanupOutcome, CleanupFailure<E>>;

impl<E: std::fmt::Debug> std::fmt::Debug for CleanupFailure<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEntry { entry } => formatter
                .debug_struct("InvalidEntry")
                .field("entry", entry)
                .finish(),
            Self::Configuration { entry } => formatter
                .debug_struct("Configuration")
                .field("entry", entry)
                .finish(),
            Self::ClientSecretUnavailable { entry } => formatter
                .debug_struct("ClientSecretUnavailable")
                .field("entry", entry)
                .finish(),
            Self::Ownership { entry, source } => formatter
                .debug_struct("Ownership")
                .field("entry", entry)
                .field("source", source)
                .finish(),
            Self::GitHubRevocation { entry, source } => formatter
                .debug_struct("GitHubRevocation")
                .field("entry", entry)
                .field("source_kind", &source.kind())
                .finish(),
            Self::CacheDeletion { entry, source } => formatter
                .debug_struct("CacheDeletion")
                .field("entry", entry)
                .field("source", source)
                .finish(),
            Self::DirectorySyncFailed { entry, source } => formatter
                .debug_struct("DirectorySyncFailed")
                .field("entry", entry)
                .field("source", source)
                .finish(),
        }
    }
}

#[derive(Debug)]
pub struct CleanupReport<E> {
    pub expired_deletions: usize,
    pub revoked_runs: usize,
    pub active_runs_skipped: usize,
    pub retained_entries: usize,
    pub failures: Vec<CleanupFailure<E>>,
}

impl<E> Default for CleanupReport<E> {
    fn default() -> Self {
        Self {
            expired_deletions: 0,
            revoked_runs: 0,
            active_runs_skipped: 0,
            retained_entries: 0,
            failures: Vec::new(),
        }
    }
}

impl<E: std::fmt::Debug> CleanupReport<E> {
    pub const fn is_complete(&self) -> bool {
        self.retained_entries == 0 && self.failures.is_empty()
    }

    fn record(&mut self, attempt: CleanupAttempt<E>) {
        match attempt {
            Ok(CleanupOutcome::NoAction) => {}
            Ok(CleanupOutcome::ExpiredDeleted) => self.expired_deletions += 1,
            Ok(CleanupOutcome::RunRevoked) => self.revoked_runs += 1,
            Ok(CleanupOutcome::ActiveRunSkipped) => self.active_runs_skipped += 1,
            Err(failure @ CleanupFailure::DirectorySyncFailed { .. }) => {
                tracing::debug!(
                    failure = ?failure,
                    "directory sync failed after deleting expired cache entry; durability is uncertain"
                );
                self.failures.push(failure);
            }
            Err(failure) => {
                tracing::debug!(failure = ?failure, "retaining cache entry for inspection or retry");
                self.retained_entries += 1;
                self.failures.push(failure);
            }
        }
    }
}

pub(super) fn cleanup_marked_run<C, S, E>(
    client: &C,
    config: &Config,
    store: &S,
    entry: &RunRecord,
) -> CleanupReport<E>
where
    C: RevokeTokenClient,
    S: RunLifecycleStore<Error = E>,
    E: std::fmt::Debug + std::fmt::Display,
{
    let mut report = CleanupReport::default();
    let attempt = match entry.state {
        RunState::CleanupPending => cleanup_run_entry(client, config, store, &entry.run_id, entry),
        RunState::Pending | RunState::Running => Err(CleanupFailure::InvalidEntry {
            entry: entry.run_id.clone(),
        }),
    };
    report.record(attempt);
    report
}

pub fn prune<C, S, E>(
    client: &C,
    config: &Config,
    store: &S,
    now: OffsetDateTime,
) -> Result<CleanupReport<E>, E>
where
    C: RevokeTokenClient,
    S: InspectRecords<Error = E> + DeleteInspectedRecord<Error = E> + RunLifecycleStore<Error = E>,
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
                cleanup_unexpired_entry(client, config, store, &label, *entry)
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

fn cleanup_unexpired_entry<C, S, E>(
    client: &C,
    config: &Config,
    store: &S,
    label: &str,
    entry: Record,
) -> CleanupAttempt<E>
where
    C: RevokeTokenClient,
    S: RunLifecycleStore<Error = E>,
    E: std::fmt::Display,
{
    match entry {
        Record::Base(_) | Record::Scoped(_) => Ok(CleanupOutcome::NoAction),
        Record::Run(entry) => cleanup_pruned_run(client, config, store, label, &entry),
    }
}

fn cleanup_pruned_run<C, S, E>(
    client: &C,
    config: &Config,
    store: &S,
    label: &str,
    entry: &RunRecord,
) -> CleanupAttempt<E>
where
    C: RevokeTokenClient,
    S: RunLifecycleStore<Error = E>,
    E: std::fmt::Display,
{
    match entry.state {
        RunState::CleanupPending => cleanup_run_entry(client, config, store, label, entry),
        RunState::Pending | RunState::Running
            if pid_is_alive(entry.wrapper_pid) || entry.child_pid.is_some_and(pid_is_alive) =>
        {
            tracing::debug!(entry = label, wrapper_pid = entry.wrapper_pid, child_pid = ?entry.child_pid, "skipping active run during pruning");
            Ok(CleanupOutcome::ActiveRunSkipped)
        }
        RunState::Pending | RunState::Running => {
            tracing::debug!(entry = label, "claiming abandoned run for cleanup");
            match store.claim_abandoned(entry) {
                Ok(claimed) => cleanup_run_entry(client, config, store, label, &claimed),
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

fn cleanup_run_entry<C, S, E>(
    client: &C,
    config: &Config,
    store: &S,
    label: &str,
    entry: &RunRecord,
) -> CleanupAttempt<E>
where
    C: RevokeTokenClient,
    S: RunLifecycleStore<Error = E>,
    E: std::fmt::Display,
{
    let label = label.to_owned();
    let Some(app) = validated_app(config, entry) else {
        tracing::debug!(
            run_id = entry.run_id,
            source_profile = entry.source_profile,
            "run token source authority no longer matches configuration"
        );
        return Err(CleanupFailure::Configuration { entry: label });
    };
    let Some(secret) = app.github_app.client_secret.as_deref() else {
        tracing::debug!(
            run_id = entry.run_id,
            source_profile = entry.source_profile,
            "run token cannot be remotely revoked because the source profile has no client secret"
        );
        return Err(CleanupFailure::ClientSecretUnavailable { entry: label });
    };
    match client.delete_token(
        &app.github_app.client_id,
        secret,
        entry.access_token.as_ref(),
    ) {
        Ok(()) => tracing::debug!(run_id = entry.run_id, "run token remotely revoked"),
        Err(source) if source.is_not_found() => {
            tracing::debug!(
                run_id = entry.run_id,
                "run token was already inactive on GitHub"
            );
        }
        Err(source) => {
            tracing::debug!(run_id = entry.run_id, error = %source, "failed to revoke run token");
            return Err(CleanupFailure::GitHubRevocation {
                entry: label,
                source,
            });
        }
    }
    match store.delete_cleanup_pending(entry) {
        Ok(_) => {
            tracing::debug!(
                run_id = entry.run_id,
                "deleted run recovery entry after remote cleanup"
            );
            Ok(CleanupOutcome::RunRevoked)
        }
        Err(source) => {
            tracing::debug!(run_id = entry.run_id, error = %source, "failed to delete run recovery entry after remote cleanup");
            Err(CleanupFailure::CacheDeletion {
                entry: label,
                source,
            })
        }
    }
}

fn validated_app<'a>(config: &'a Config, entry: &RunRecord) -> Option<&'a AppProfile> {
    match super::provenance::for_source(
        config,
        &entry.source_profile,
        &entry.source_authority_fingerprint,
    ) {
        super::provenance::ConfiguredAuthority::Match(app) => Some(app),
        super::provenance::ConfiguredAuthority::Mismatch
        | super::provenance::ConfiguredAuthority::Missing => None,
    }
}

const fn expiry(entry: &Record) -> TokenExpiry {
    entry.expires_at()
}

#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    let Ok(raw) = i32::try_from(pid) else {
        return true;
    };
    let Some(pid) = rustix::process::Pid::from_raw(raw) else {
        return true;
    };
    !matches!(
        rustix::process::test_kill_process(pid),
        Err(error) if error == rustix::io::Errno::SRCH
    )
}

#[cfg(not(unix))]
fn pid_is_alive(_pid: u32) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{Record, compute_run_cache_key, load_cache_entry, write_test_entry};
    use crate::credential::{TokenExpiry, authority_fingerprint};
    use crate::run::{RunRecord, RunState};
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

    fn config() -> Config {
        r#"
version = 1
default_profile = "reader"
[profile.developer]
github_app.account = "acme"
github_app.client_id = "id"
github_app.client_secret = "secret"
[profile.reader]
source = "developer"
repo = "acme/api"
permissions = { contents = "read" }
"#
        .parse()
        .unwrap()
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

    fn client() -> MockClient {
        MockClient {
            revoked: RefCell::new(Vec::new()),
            fail: Cell::new(false),
        }
    }

    #[test]
    fn prune_skips_active_runs_and_revokes_abandoned_runs() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        for (id, wrapper) in [
            ("active", std::process::id()),
            ("abandoned", i32::MAX as u32),
        ] {
            write_test_entry(
                &cache_dir,
                &compute_run_cache_key(id),
                &run_entry(
                    id,
                    RunState::Running,
                    wrapper,
                    Some(i32::MAX as u32),
                    now + Duration::hours(1),
                ),
            )
            .unwrap();
        }
        let client = client();
        let store = crate::cache::CacheStore::new(&cache_dir);
        let report = prune(&client, &config(), &store, now).unwrap();
        assert_eq!(report.active_runs_skipped, 1);
        assert_eq!(report.revoked_runs, 1);
        assert!(report.is_complete());
        assert_eq!(&*client.revoked.borrow(), &["token-abandoned"]);
        assert!(
            load_cache_entry(&cache_dir, &compute_run_cache_key("active"))
                .unwrap()
                .is_some()
        );
        assert!(
            load_cache_entry(&cache_dir, &compute_run_cache_key("abandoned"))
                .unwrap()
                .is_none()
        );
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
                RunState::CleanupPending,
                i32::MAX as u32,
                None,
                now - Duration::seconds(1),
            ),
        )
        .unwrap();
        let client = client();
        let store = crate::cache::CacheStore::new(&cache_dir);
        let report = prune(&client, &config(), &store, now).unwrap();
        assert_eq!(report.expired_deletions, 1);
        assert!(client.revoked.borrow().is_empty());
        assert!(load_cache_entry(&cache_dir, &key).unwrap().is_none());
    }

    #[test]
    fn prune_does_not_revoke_with_mismatched_authority() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        let key = compute_run_cache_key("mismatched");
        let mut cached = run_entry(
            "mismatched",
            RunState::Running,
            i32::MAX as u32,
            Some(i32::MAX as u32),
            now + Duration::hours(1),
        );
        let Record::Run(entry) = &mut cached else {
            unreachable!("run_entry returned a non-run entry")
        };
        entry.source_authority_fingerprint = authority_fingerprint("other-id", "different");
        write_test_entry(&cache_dir, &key, &cached).unwrap();

        let client = client();
        let store = crate::cache::CacheStore::new(&cache_dir);
        let report = prune(&client, &config(), &store, now).unwrap();

        assert!(client.revoked.borrow().is_empty());
        assert_eq!(report.retained_entries, 1);
        assert!(matches!(
            report.failures.as_slice(),
            [CleanupFailure::Configuration { .. }]
        ));
        assert!(matches!(
            load_cache_entry(&cache_dir, &key).unwrap(),
            Some(Record::Run(RunRecord {
                state: RunState::CleanupPending,
                ..
            }))
        ));
    }

    #[test]
    fn prune_retains_claimed_abandoned_run_when_remote_revocation_fails() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        let key = compute_run_cache_key("failed-revocation");
        write_test_entry(
            &cache_dir,
            &key,
            &run_entry(
                "failed-revocation",
                RunState::Running,
                i32::MAX as u32,
                Some(i32::MAX as u32),
                now + Duration::hours(1),
            ),
        )
        .unwrap();
        let client = client();
        client.fail.set(true);

        let store = crate::cache::CacheStore::new(&cache_dir);
        let report = prune(&client, &config(), &store, now).unwrap();

        assert_eq!(report.retained_entries, 1);
        assert!(matches!(
            report.failures.as_slice(),
            [CleanupFailure::GitHubRevocation { .. }]
        ));
        assert_eq!(&*client.revoked.borrow(), &["token-failed-revocation"]);
        assert!(matches!(
            load_cache_entry(&cache_dir, &key).unwrap(),
            Some(Record::Run(RunRecord {
                state: RunState::CleanupPending,
                ..
            }))
        ));
    }

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
        let report = prune(&client, &config(), &store, now).unwrap();

        assert_eq!(report.expired_deletions, 0);
        assert_eq!(
            report.retained_entries, 0,
            "file unlinked; must not be counted as retained"
        );
        assert_eq!(report.failures.len(), 1);
        assert!(matches!(
            report.failures.as_slice(),
            [CleanupFailure::DirectorySyncFailed { .. }]
        ));
        assert!(!report.is_complete());
        assert!(load_cache_entry(&cache_dir, &key).unwrap().is_none());
    }
}
