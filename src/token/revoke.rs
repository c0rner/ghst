use crate::config::Config;
use crate::token::store::{
    BeginRevocation, DeleteInspectedRecord, DeleteOutcome, InspectionState, Record,
    RecordInspection, RevocationBatch, RevocationSelection,
};
use crate::token::{RemoteError, RevokeTokenClient};
use time::OffsetDateTime;

pub enum RevokeFailure<E> {
    InvalidEntry {
        entry: String,
    },
    MissingAppCredentials {
        entry: String,
    },
    ClientSecretUnavailable {
        entry: String,
    },
    AuthorityMismatch {
        entry: String,
    },
    GitHubRevocation {
        entry: String,
        source: RemoteError,
    },
    CacheDeletion {
        entry: String,
        source: E,
        remotely_revoked: bool,
    },
    DirectorySyncFailed {
        entry: String,
        source: E,
        remotely_revoked: bool,
    },
    DeletedRecordChanged {
        entry: String,
        remotely_revoked: bool,
    },
    DeletedRecordMissing {
        entry: String,
        remotely_revoked: bool,
    },
}

impl<E: std::fmt::Debug> std::fmt::Debug for RevokeFailure<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEntry { entry } => formatter
                .debug_struct("InvalidEntry")
                .field("entry", entry)
                .finish(),
            Self::MissingAppCredentials { entry } => formatter
                .debug_struct("MissingAppCredentials")
                .field("entry", entry)
                .finish(),
            Self::ClientSecretUnavailable { entry } => formatter
                .debug_struct("ClientSecretUnavailable")
                .field("entry", entry)
                .finish(),
            Self::AuthorityMismatch { entry } => formatter
                .debug_struct("AuthorityMismatch")
                .field("entry", entry)
                .finish(),
            Self::GitHubRevocation { entry, source } => formatter
                .debug_struct("GitHubRevocation")
                .field("entry", entry)
                .field("source_kind", &source.kind())
                .finish(),
            Self::CacheDeletion {
                entry,
                source,
                remotely_revoked,
            } => formatter
                .debug_struct("CacheDeletion")
                .field("entry", entry)
                .field("source", source)
                .field("remotely_revoked", remotely_revoked)
                .finish(),
            Self::DirectorySyncFailed {
                entry,
                source,
                remotely_revoked,
            } => formatter
                .debug_struct("DirectorySyncFailed")
                .field("entry", entry)
                .field("source", source)
                .field("remotely_revoked", remotely_revoked)
                .finish(),
            Self::DeletedRecordChanged {
                entry,
                remotely_revoked,
            } => formatter
                .debug_struct("DeletedRecordChanged")
                .field("entry", entry)
                .field("remotely_revoked", remotely_revoked)
                .finish(),
            Self::DeletedRecordMissing {
                entry,
                remotely_revoked,
            } => formatter
                .debug_struct("DeletedRecordMissing")
                .field("entry", entry)
                .field("remotely_revoked", remotely_revoked)
                .finish(),
        }
    }
}

#[derive(Debug)]
pub struct RevokeReport<E> {
    pub remotely_inactive: usize,
    pub local_only: usize,
    pub retained: usize,
    pub failures: Vec<RevokeFailure<E>>,
}

impl<E> Default for RevokeReport<E> {
    fn default() -> Self {
        Self {
            remotely_inactive: 0,
            local_only: 0,
            retained: 0,
            failures: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum RevokeOneOutcome<E> {
    Revoked(RevokeReport<E>),
    NotFound,
    Ambiguous,
}

pub fn revoke_all<C, S, E>(
    client: &C,
    config: &Config,
    store: &S,
    now: OffsetDateTime,
) -> Result<RevokeReport<E>, E>
where
    C: RevokeTokenClient,
    S: BeginRevocation<Error = E> + DeleteInspectedRecord<Error = E>,
    E: std::error::Error + 'static,
{
    let batch = store.begin_revocation(RevocationSelection::All)?;
    let snapshots = match batch {
        RevocationBatch::Selected(snapshots) => snapshots,
        RevocationBatch::NotFound | RevocationBatch::Ambiguous => Vec::new(),
    };
    Ok(process_revocation_batch(
        client, config, store, snapshots, now,
    ))
}

pub fn revoke_one<C, S, E>(
    client: &C,
    config: &Config,
    store: &S,
    cache_id: &str,
    now: OffsetDateTime,
) -> Result<RevokeOneOutcome<E>, E>
where
    C: RevokeTokenClient,
    S: BeginRevocation<Error = E> + DeleteInspectedRecord<Error = E>,
    E: std::error::Error + 'static,
{
    let batch = store.begin_revocation(RevocationSelection::One(cache_id))?;
    match batch {
        RevocationBatch::NotFound => Ok(RevokeOneOutcome::NotFound),
        RevocationBatch::Ambiguous => Ok(RevokeOneOutcome::Ambiguous),
        RevocationBatch::Selected(snapshots) => {
            let report = process_revocation_batch(client, config, store, snapshots, now);
            Ok(RevokeOneOutcome::Revoked(report))
        }
    }
}

fn process_revocation_batch<C, S, E>(
    client: &C,
    config: &Config,
    store: &S,
    snapshots: Vec<RecordInspection>,
    now: OffsetDateTime,
) -> RevokeReport<E>
where
    C: RevokeTokenClient,
    S: DeleteInspectedRecord<Error = E>,
    E: std::error::Error + 'static,
{
    let mut report = RevokeReport::default();
    tracing::debug!(
        entries = snapshots.len(),
        "processing selected records for revocation"
    );
    for snapshot in snapshots {
        process_snapshot(client, config, store, snapshot, now, &mut report);
    }
    report
}

#[derive(Clone, Copy)]
enum DeletionIntent {
    RemotelyRevoked,
    LocalOnly(Option<LocalOnlyReason>),
}

#[derive(Clone, Copy)]
enum LocalOnlyReason {
    MissingAppCredentials,
    ClientSecretUnavailable,
    AuthorityMismatch,
}

fn process_snapshot<C, S, E>(
    client: &C,
    config: &Config,
    store: &S,
    snapshot: RecordInspection,
    now: OffsetDateTime,
    report: &mut RevokeReport<E>,
) where
    C: RevokeTokenClient,
    S: DeleteInspectedRecord<Error = E>,
    E: std::error::Error + 'static,
{
    let label = snapshot.label;
    tracing::debug!(entry = label, "processing cached credential for revocation");
    let (Some(slot_id), InspectionState::Current(entry)) = (snapshot.slot_id, snapshot.state)
    else {
        tracing::debug!(
            entry = label,
            "cache entry is invalid; retaining without deletion or remote revocation"
        );
        report.retained += 1;
        report
            .failures
            .push(RevokeFailure::InvalidEntry { entry: label });
        return;
    };

    if !entry.is_safe_to_handoff_at(now) {
        tracing::debug!(
            entry = label,
            "cached credential is expired or inside the handoff margin; deleting locally without remote revocation"
        );
        finalize_deletion(
            store,
            &slot_id,
            &entry,
            &label,
            DeletionIntent::LocalOnly(None),
            report,
        );
        return;
    }

    match crate::token::provenance::for_entry(config, &entry) {
        crate::token::provenance::ConfiguredAuthority::Match(app) => {
            revoke_matching_authority(client, store, app, &slot_id, &entry, &label, report);
        }
        crate::token::provenance::ConfiguredAuthority::Mismatch => {
            tracing::debug!(
                entry = label,
                "cached credential authority differs from configuration; deleting locally only"
            );
            finalize_deletion(
                store,
                &slot_id,
                &entry,
                &label,
                DeletionIntent::LocalOnly(Some(LocalOnlyReason::AuthorityMismatch)),
                report,
            );
        }
        crate::token::provenance::ConfiguredAuthority::Missing => {
            tracing::debug!(
                entry = label,
                "cached credential source profile is missing; deleting locally only"
            );
            finalize_deletion(
                store,
                &slot_id,
                &entry,
                &label,
                DeletionIntent::LocalOnly(Some(LocalOnlyReason::MissingAppCredentials)),
                report,
            );
        }
    }
}

fn revoke_matching_authority<C, S, E>(
    client: &C,
    store: &S,
    app: &crate::config::AppProfile,
    slot_id: &str,
    entry: &Record,
    label: &str,
    report: &mut RevokeReport<E>,
) where
    C: RevokeTokenClient,
    S: DeleteInspectedRecord<Error = E>,
    E: std::error::Error + 'static,
{
    let Some(secret) = app.github_app.client_secret.as_deref() else {
        tracing::debug!(
            entry = label,
            "client secret unavailable; deleting cached credential locally only"
        );
        finalize_deletion(
            store,
            slot_id,
            entry,
            label,
            DeletionIntent::LocalOnly(Some(LocalOnlyReason::ClientSecretUnavailable)),
            report,
        );
        return;
    };
    match client.delete_token(
        &app.github_app.client_id,
        secret,
        entry.access_token().as_ref(),
    ) {
        Ok(()) => {
            tracing::debug!(entry = label, "cached credential remotely revoked");
            finalize_deletion(
                store,
                slot_id,
                entry,
                label,
                DeletionIntent::RemotelyRevoked,
                report,
            );
        }
        Err(source) if source.is_not_found() => {
            tracing::debug!(
                entry = label,
                "cached credential was already inactive on GitHub"
            );
            finalize_deletion(
                store,
                slot_id,
                entry,
                label,
                DeletionIntent::RemotelyRevoked,
                report,
            );
        }
        Err(source) => {
            tracing::debug!(
                entry = label,
                error = %source,
                "failed to remotely revoke cached credential; retaining it for retry"
            );
            report.retained += 1;
            report.failures.push(RevokeFailure::GitHubRevocation {
                entry: label.to_owned(),
                source,
            });
        }
    }
}

fn finalize_deletion<S, E>(
    store: &S,
    slot_id: &str,
    expected: &Record,
    label: &str,
    intent: DeletionIntent,
    report: &mut RevokeReport<E>,
) where
    S: DeleteInspectedRecord<Error = E>,
    E: std::error::Error + 'static,
{
    let remotely_revoked = matches!(intent, DeletionIntent::RemotelyRevoked);
    match store.delete_exact_record(slot_id, expected) {
        Ok(DeleteOutcome::Deleted) => match intent {
            DeletionIntent::RemotelyRevoked => {
                report.remotely_inactive += 1;
                tracing::debug!(
                    entry = label,
                    "deleted remotely inactive credential from local storage"
                );
            }
            DeletionIntent::LocalOnly(None) => {
                report.local_only += 1;
                tracing::debug!(
                    entry = label,
                    "deleted expired credential from local storage only"
                );
            }
            DeletionIntent::LocalOnly(Some(reason)) => {
                report.local_only += 1;
                tracing::debug!(entry = label, "deleted credential from local storage only");
                match reason {
                    LocalOnlyReason::MissingAppCredentials => {
                        report.failures.push(RevokeFailure::MissingAppCredentials {
                            entry: label.to_owned(),
                        });
                    }
                    LocalOnlyReason::ClientSecretUnavailable => {
                        report
                            .failures
                            .push(RevokeFailure::ClientSecretUnavailable {
                                entry: label.to_owned(),
                            });
                    }
                    LocalOnlyReason::AuthorityMismatch => {
                        report.failures.push(RevokeFailure::AuthorityMismatch {
                            entry: label.to_owned(),
                        });
                    }
                }
            }
        },
        Ok(DeleteOutcome::Changed) => {
            tracing::debug!(
                entry = label,
                remotely_revoked,
                "cached credential changed during revocation; retaining"
            );
            report.retained += 1;
            report.failures.push(RevokeFailure::DeletedRecordChanged {
                entry: label.to_owned(),
                remotely_revoked,
            });
        }
        Ok(DeleteOutcome::Missing) => {
            tracing::debug!(
                entry = label,
                remotely_revoked,
                "cached credential disappeared during revocation"
            );
            report.failures.push(RevokeFailure::DeletedRecordMissing {
                entry: label.to_owned(),
                remotely_revoked,
            });
        }
        Ok(DeleteOutcome::UnlinkedSyncFailed(source)) => {
            tracing::debug!(
                entry = label,
                error = %source,
                remotely_revoked,
                "directory sync failed after credential deletion; durability is uncertain"
            );
            report.failures.push(RevokeFailure::DirectorySyncFailed {
                entry: label.to_owned(),
                source,
                remotely_revoked,
            });
        }
        Err(source) => {
            tracing::debug!(
                entry = label,
                error = %source,
                remotely_revoked,
                "failed to delete credential from storage"
            );
            report.retained += 1;
            report.failures.push(RevokeFailure::CacheDeletion {
                entry: label.to_owned(),
                source,
                remotely_revoked,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{
        CacheStore, Record, compute_cache_key, compute_run_cache_key, list_all_cache_entries,
        save_cache_entry,
    };
    use crate::credential::{
        AccessToken, BaseCredential, ScopedCredential, TokenExpiry, authority_fingerprint,
    };
    use crate::run::{RunRecord, RunState};
    use std::cell::{Cell, RefCell};
    use std::path::Path;
    use time::Duration;

    struct MockClient(Cell<usize>);

    impl RevokeTokenClient for MockClient {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            _access_token: &str,
        ) -> Result<(), RemoteError> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
    }

    struct RecordingClient {
        revoked: RefCell<Vec<String>>,
        fails: bool,
    }

    impl RevokeTokenClient for RecordingClient {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            access_token: &str,
        ) -> Result<(), RemoteError> {
            self.revoked.borrow_mut().push(access_token.to_owned());
            if self.fails {
                Err(RemoteError::Http {
                    status: 500,
                    message: "revocation failed".into(),
                })
            } else {
                Ok(())
            }
        }
    }

    fn config(secret: bool) -> Config {
        let secret = if secret {
            "github_app.client_secret = \"secret\""
        } else {
            ""
        };
        format!(
            "version = 1\ndefault_profile = \"developer\"\n[profile.developer]\ngithub_app.account = \"acme\"\ngithub_app.client_id = \"id\"\n{secret}\n"
        )
        .parse()
        .unwrap()
    }

    fn cache_base(cache_dir: &Path, expiry: OffsetDateTime) {
        let entry = Record::Base(BaseCredential {
            profile: "developer".into(),
            authority_fingerprint: authority_fingerprint("id", "acme"),
            github_user: "octocat".into(),
            expires_at: TokenExpiry::new(expiry),
            access_token: AccessToken::from("base-token"),
        });
        save_cache_entry(
            cache_dir,
            &crate::token::base_cache_key("developer"),
            &entry,
        )
        .unwrap();
    }

    #[test]
    fn live_secretless_entry_is_local_only_and_incomplete() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_base(&cache_dir, OffsetDateTime::now_utc() + Duration::hours(1));
        let client = MockClient(Cell::new(0));
        let store = CacheStore::new(&cache_dir);
        let report =
            revoke_all(&client, &config(false), &store, OffsetDateTime::now_utc()).unwrap();
        assert_eq!(report.local_only, 1);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(client.0.get(), 0);
        assert!(list_all_cache_entries(&cache_dir).unwrap().is_empty());
    }

    #[test]
    fn live_entry_is_revoked_and_expired_entry_is_deleted_locally() {
        for (offset, remote) in [(Duration::hours(1), 1), (Duration::hours(-1), 0)] {
            let temp = tempfile::tempdir().unwrap();
            let cache_dir = temp.path().join("cache");
            cache_base(&cache_dir, OffsetDateTime::now_utc() + offset);
            let client = MockClient(Cell::new(0));
            let store = CacheStore::new(&cache_dir);
            let report =
                revoke_all(&client, &config(true), &store, OffsetDateTime::now_utc()).unwrap();
            assert_eq!(client.0.get(), remote);
            assert!(report.failures.is_empty());
            assert!(list_all_cache_entries(&cache_dir).unwrap().is_empty());
        }
    }

    #[test]
    fn invalid_entry_is_retained_and_reported_as_failure() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        crate::cache::ensure_cache_dir(&cache_dir).unwrap();
        let corrupt_path = cache_dir.join("corrupt.json");
        std::fs::write(&corrupt_path, b"invalid json").unwrap();
        let client = MockClient(Cell::new(0));
        let store = CacheStore::new(&cache_dir);
        let report = revoke_all(&client, &config(true), &store, OffsetDateTime::now_utc()).unwrap();
        assert_eq!(report.remotely_inactive, 0);
        assert_eq!(report.local_only, 0);
        assert_eq!(report.retained, 1);
        assert_eq!(client.0.get(), 0);
        assert!(matches!(
            report.failures.as_slice(),
            [RevokeFailure::InvalidEntry { entry }] if entry == "corrupt.json"
        ));
        assert!(corrupt_path.exists());
    }

    #[test]
    fn targeted_revocation_only_processes_the_selected_cache_slot() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        cache_base(&cache_dir, now + Duration::hours(1));
        let scoped_key = compute_cache_key("reader", "acme/api");
        save_cache_entry(
            &cache_dir,
            &scoped_key,
            &Record::Scoped(ScopedCredential {
                profile: "reader".into(),
                source_profile: "developer".into(),
                source_authority_fingerprint: authority_fingerprint("id", "acme"),
                parent_generation: "generation".into(),
                policy_fingerprint: "policy".into(),
                github_user: "octocat".into(),
                repo_scope: "acme/api".into(),
                expires_at: TokenExpiry::new(now + Duration::hours(1)),
                access_token: AccessToken::from("scoped-token"),
            }),
        )
        .unwrap();
        let client = RecordingClient {
            revoked: RefCell::new(Vec::new()),
            fails: false,
        };
        let store = CacheStore::new(&cache_dir);

        let report = match revoke_one(
            &client,
            &config(true),
            &store,
            &scoped_key[..crate::cache::MIN_CACHE_ID_LENGTH],
            now,
        )
        .unwrap()
        {
            RevokeOneOutcome::Revoked(report) => report,
            other => panic!("unexpected outcome: {other:?}"),
        };

        assert_eq!(report.remotely_inactive, 1);
        assert!(report.failures.is_empty());
        assert_eq!(&*client.revoked.borrow(), &["scoped-token"]);
        let entries = list_all_cache_entries(&cache_dir).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, crate::token::base_cache_key("developer"));

        assert!(matches!(
            revoke_one(&client, &config(true), &store, &scoped_key, now).unwrap(),
            RevokeOneOutcome::NotFound
        ));
    }

    #[test]
    fn targeted_remote_failure_retains_the_selected_entry_for_retry() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        cache_base(&cache_dir, now + Duration::hours(1));
        let base_key = crate::token::base_cache_key("developer");
        let client = RecordingClient {
            revoked: RefCell::new(Vec::new()),
            fails: true,
        };
        let store = CacheStore::new(&cache_dir);

        let report = match revoke_one(&client, &config(true), &store, &base_key, now).unwrap() {
            RevokeOneOutcome::Revoked(report) => report,
            other => panic!("unexpected outcome: {other:?}"),
        };

        assert_eq!(report.retained, 1);
        assert!(matches!(
            report.failures.as_slice(),
            [RevokeFailure::GitHubRevocation { .. }]
        ));
        assert_eq!(list_all_cache_entries(&cache_dir).unwrap().len(), 1);
    }

    #[test]
    fn ambiguous_cache_id_does_not_revoke_or_delete_any_entry() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        cache_base(&cache_dir, now + Duration::hours(1));
        let first = format!("0123456{}", "a".repeat(57));
        let second = format!("0123456{}", "b".repeat(57));
        std::fs::write(cache_dir.join(format!("{first}.json")), b"{").unwrap();
        std::fs::write(cache_dir.join(format!("{second}.json")), b"{").unwrap();
        let client = RecordingClient {
            revoked: RefCell::new(Vec::new()),
            fails: false,
        };
        let store = CacheStore::new(&cache_dir);

        let outcome = revoke_one(&client, &config(true), &store, "0123456", now).unwrap();

        assert!(matches!(outcome, RevokeOneOutcome::Ambiguous));
        assert!(client.revoked.borrow().is_empty());
        assert!(cache_dir.join(format!("{first}.json")).exists());
        assert!(cache_dir.join(format!("{second}.json")).exists());
    }

    #[test]
    fn authority_mismatch_is_local_only_for_every_cache_kind() {
        let now = OffsetDateTime::now_utc();
        let changed: Config = "version = 1\ndefault_profile = \"developer\"\n[profile.developer]\ngithub_app.account = \"different\"\ngithub_app.client_id = \"other-id\"\ngithub_app.client_secret = \"secret\"\n"
            .parse()
            .unwrap();
        for (key, entry) in mismatched_entries(now + Duration::hours(1)) {
            let temp = tempfile::tempdir().unwrap();
            let cache_dir = temp.path().join("cache");
            save_cache_entry(&cache_dir, &key, &entry).unwrap();
            let client = MockClient(Cell::new(0));
            let store = CacheStore::new(&cache_dir);
            let report = revoke_all(&client, &changed, &store, now).unwrap();
            assert_eq!(client.0.get(), 0);
            assert_eq!(report.remotely_inactive, 0);
            assert_eq!(report.local_only, 1);
            assert!(matches!(
                report.failures.as_slice(),
                [RevokeFailure::AuthorityMismatch { .. }]
            ));
            assert!(list_all_cache_entries(&cache_dir).unwrap().is_empty());
        }
    }

    fn mismatched_entries(expiry: OffsetDateTime) -> [(String, Record); 3] {
        let authority = authority_fingerprint("id", "acme");
        [
            (
                crate::token::base_cache_key("developer"),
                Record::Base(BaseCredential {
                    profile: "developer".into(),
                    authority_fingerprint: authority.clone(),
                    github_user: "octocat".into(),
                    expires_at: TokenExpiry::new(expiry),
                    access_token: AccessToken::from("base-token"),
                }),
            ),
            (
                compute_cache_key("reader", "acme/api"),
                Record::Scoped(ScopedCredential {
                    profile: "reader".into(),
                    source_profile: "developer".into(),
                    source_authority_fingerprint: authority.clone(),
                    parent_generation: "generation".into(),
                    policy_fingerprint: "policy".into(),
                    github_user: "octocat".into(),
                    repo_scope: "acme/api".into(),
                    expires_at: TokenExpiry::new(expiry),
                    access_token: AccessToken::from("scoped-token"),
                }),
            ),
            (
                compute_run_cache_key("run-1"),
                Record::Run(RunRecord {
                    run_id: "run-1".into(),
                    state: RunState::Running,
                    wrapper_pid: 100,
                    child_pid: Some(101),
                    command: "true".into(),
                    profile: "reader".into(),
                    source_profile: "developer".into(),
                    source_authority_fingerprint: authority,
                    github_user: "octocat".into(),
                    repo_scope: "acme/api".into(),
                    expires_at: TokenExpiry::new(expiry),
                    access_token: AccessToken::from("run-token"),
                }),
            ),
        ]
    }

    struct ConcurrentPausingClient {
        started_tx: std::sync::mpsc::Sender<()>,
        proceed_rx: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl RevokeTokenClient for ConcurrentPausingClient {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            _access_token: &str,
        ) -> Result<(), RemoteError> {
            self.started_tx.send(()).unwrap();
            self.proceed_rx
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            Ok(())
        }
    }

    #[test]
    fn revocation_does_not_hold_cache_lock_across_network() {
        use std::sync::Arc;

        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        cache_base(&cache_dir, now + Duration::hours(1));

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (proceed_tx, proceed_rx) = std::sync::mpsc::channel();

        let client = Arc::new(ConcurrentPausingClient {
            started_tx,
            proceed_rx: std::sync::Mutex::new(proceed_rx),
        });

        let client_clone = Arc::clone(&client);
        let cache_dir_clone = cache_dir.clone();
        let worker = std::thread::spawn(move || {
            let store = CacheStore::new(&cache_dir_clone);
            revoke_all(&*client_clone, &config(true), &store, now).unwrap()
        });

        started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("worker did not start network call in time");

        // While the worker is blocked in HTTP, another store instance acquires the cache lock.
        // If the workflow held the lock across HTTP, this operation would block or deadlock.
        // We use a separate thread and bounded timeout to ensure the test fails fast instead of hanging.
        let (lock_tx, lock_rx) = std::sync::mpsc::channel();
        let locker = std::thread::spawn(move || {
            let store2 = CacheStore::new(&cache_dir);
            let batch = store2
                .begin_revocation(crate::token::store::RevocationSelection::All)
                .expect("second adapter must acquire exclusive lock while HTTP is paused");
            lock_tx.send(batch).unwrap();
        });

        let batch = lock_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("second adapter timed out acquiring exclusive lock; network held lock");
        assert!(matches!(
            batch,
            crate::token::store::RevocationBatch::Selected(_)
        ));

        proceed_tx.send(()).unwrap();
        let report = worker.join().unwrap();
        locker.join().unwrap();
        assert_eq!(report.remotely_inactive, 1);
        assert!(report.failures.is_empty());
    }

    #[test]
    fn concurrent_replacement_during_revocation_survives_exact_finalization() {
        use std::sync::Arc;

        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        cache_base(&cache_dir, now + Duration::hours(1));

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (proceed_tx, proceed_rx) = std::sync::mpsc::channel();

        let client = Arc::new(ConcurrentPausingClient {
            started_tx,
            proceed_rx: std::sync::Mutex::new(proceed_rx),
        });

        let client_clone = Arc::clone(&client);
        let cache_dir_clone = cache_dir.clone();
        let worker = std::thread::spawn(move || {
            let store = CacheStore::new(&cache_dir_clone);
            revoke_all(&*client_clone, &config(true), &store, now).unwrap()
        });

        started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("worker did not start network call in time");

        // While worker is paused in HTTP, replace the entry on disk
        let key = crate::token::base_cache_key("developer");
        let path = cache_dir.join(format!("{key}.json"));
        let expiry = TokenExpiry::new(now + Duration::hours(2));
        let json = format!(
            r#"{{"version": 5, "kind": "base", "profile": "developer", "authority_fingerprint": "{}", "github_user": "octocat", "expires_at": "{expiry}", "access_token": "newer-base-token"}}"#,
            authority_fingerprint("id", "acme")
        );
        std::fs::write(&path, json).unwrap();

        proceed_tx.send(()).unwrap();
        let report = worker.join().unwrap();

        assert_eq!(report.remotely_inactive, 0);
        assert_eq!(report.retained, 1);
        assert!(matches!(
            report.failures.as_slice(),
            [RevokeFailure::DeletedRecordChanged { .. }]
        ));

        // The replacement survives intact
        let on_disk =
            crate::cache::load_cache_entry(&cache_dir, &crate::token::base_cache_key("developer"))
                .unwrap()
                .unwrap();
        assert_eq!(on_disk.access_token().as_ref(), "newer-base-token");
    }

    #[test]
    fn handoff_margin_exact_boundaries_inside_and_outside_30_seconds() {
        let now = OffsetDateTime::now_utc();

        // 1. Inside margin (29s remaining): deleted locally without remote call
        {
            let temp = tempfile::tempdir().unwrap();
            let cache_dir = temp.path().join("cache");
            cache_base(&cache_dir, now + Duration::seconds(29));
            let client = MockClient(Cell::new(0));
            let store = CacheStore::new(&cache_dir);
            let report = revoke_all(&client, &config(true), &store, now).unwrap();
            assert_eq!(client.0.get(), 0, "must not call GitHub inside margin");
            assert_eq!(report.local_only, 1);
            assert_eq!(report.remotely_inactive, 0);
            assert_eq!(report.retained, 0);
            assert!(report.failures.is_empty());
            assert!(list_all_cache_entries(&cache_dir).unwrap().is_empty());
        }

        // 2. Outside margin (31s remaining): remote revocation executed
        {
            let temp = tempfile::tempdir().unwrap();
            let cache_dir = temp.path().join("cache");
            cache_base(&cache_dir, now + Duration::seconds(31));
            let client = MockClient(Cell::new(0));
            let store = CacheStore::new(&cache_dir);
            let report = revoke_all(&client, &config(true), &store, now).unwrap();
            assert_eq!(client.0.get(), 1, "must call GitHub outside margin");
            assert_eq!(report.remotely_inactive, 1);
            assert_eq!(report.local_only, 0);
            assert_eq!(report.retained, 0);
            assert!(report.failures.is_empty());
            assert!(list_all_cache_entries(&cache_dir).unwrap().is_empty());
        }
    }

    #[test]
    fn active_run_revocation_deletes_exact_record() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        let run_key = compute_run_cache_key("active-run-1");
        let run = Record::Run(RunRecord {
            run_id: "active-run-1".into(),
            state: RunState::Running,
            wrapper_pid: 100,
            child_pid: Some(101),
            command: "sleep 10".into(),
            profile: "reader".into(),
            source_profile: "developer".into(),
            source_authority_fingerprint: authority_fingerprint("id", "acme"),
            github_user: "octocat".into(),
            repo_scope: "acme/api".into(),
            expires_at: TokenExpiry::new(now + Duration::hours(1)),
            access_token: AccessToken::from("active-run-token"),
        });
        save_cache_entry(&cache_dir, &run_key, &run).unwrap();

        let client = RecordingClient {
            revoked: RefCell::new(Vec::new()),
            fails: false,
        };
        let store = CacheStore::new(&cache_dir);
        let report = revoke_all(&client, &config(true), &store, now).unwrap();

        assert_eq!(report.remotely_inactive, 1);
        assert_eq!(report.failures.len(), 0);
        assert_eq!(&*client.revoked.borrow(), &["active-run-token"]);
        assert!(list_all_cache_entries(&cache_dir).unwrap().is_empty());
    }

    struct NotFoundClient;

    impl RevokeTokenClient for NotFoundClient {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            _access_token: &str,
        ) -> Result<(), RemoteError> {
            Err(RemoteError::Http {
                status: 404,
                message: "Not Found".into(),
            })
        }
    }

    #[test]
    fn github_404_already_inactive_is_treated_as_successful() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        cache_base(&cache_dir, now + Duration::hours(1));

        let store = CacheStore::new(&cache_dir);
        let report = revoke_all(&NotFoundClient, &config(true), &store, now).unwrap();
        assert_eq!(report.remotely_inactive, 1);
        assert_eq!(report.retained, 0);
        assert!(report.failures.is_empty());
        assert!(list_all_cache_entries(&cache_dir).unwrap().is_empty());
    }

    #[test]
    fn unsupported_schema_and_inconsistent_metadata_are_retained() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        crate::cache::ensure_cache_dir(&cache_dir).unwrap();
        let now = OffsetDateTime::now_utc();

        let unsupported_path = cache_dir.join(format!("{}.json", compute_cache_key("dev1", "all")));
        std::fs::write(
            &unsupported_path,
            r#"{"version": 99, "kind": "base", "profile": "dev1"}"#,
        )
        .unwrap();

        let inconsistent_path =
            cache_dir.join(format!("{}.json", compute_cache_key("dev2", "all")));
        let json = format!(
            r#"{{"version": 5, "kind": "base", "profile": "wrong_profile", "authority_fingerprint": "{}", "github_user": "octocat", "expires_at": "{}", "access_token": "token"}}"#,
            authority_fingerprint("id", "acme"),
            (now + Duration::hours(1))
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        );
        std::fs::write(&inconsistent_path, json).unwrap();

        let client = MockClient(Cell::new(0));
        let store = CacheStore::new(&cache_dir);
        let report = revoke_all(&client, &config(true), &store, now).unwrap();

        assert_eq!(client.0.get(), 0);
        assert_eq!(report.remotely_inactive, 0);
        assert_eq!(report.local_only, 0);
        assert_eq!(report.retained, 2);
        assert_eq!(report.failures.len(), 2);
        assert!(unsupported_path.exists());
        assert!(inconsistent_path.exists());
    }

    struct SequentialStatusClient {
        calls: Cell<usize>,
    }

    impl RevokeTokenClient for SequentialStatusClient {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            _access_token: &str,
        ) -> Result<(), RemoteError> {
            let count = self.calls.get();
            self.calls.set(count + 1);
            if count == 0 {
                Ok(())
            } else {
                Err(RemoteError::Http {
                    status: 404,
                    message: "Not Found".into(),
                })
            }
        }
    }

    #[test]
    fn concurrent_revokers_select_same_token_and_second_reports_missing_with_no_loss() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        cache_base(&cache_dir, now + Duration::hours(1));

        let client = SequentialStatusClient {
            calls: Cell::new(0),
        };
        let store = CacheStore::new(&cache_dir);

        // Both revokers snapshot the same cache state before deletion begins
        let batch1 = match store
            .begin_revocation(crate::token::store::RevocationSelection::All)
            .unwrap()
        {
            RevocationBatch::Selected(s) => s,
            other => panic!("expected selected batch, got {other:?}"),
        };
        let batch2 = match store
            .begin_revocation(crate::token::store::RevocationSelection::All)
            .unwrap()
        {
            RevocationBatch::Selected(s) => s,
            other => panic!("expected selected batch, got {other:?}"),
        };

        // Revoker 1 completes remote deletion and removes the exact record
        let report1 = process_revocation_batch(&client, &config(true), &store, batch1, now);
        assert_eq!(report1.remotely_inactive, 1);
        assert_eq!(report1.local_only, 0);
        assert_eq!(report1.retained, 0);
        assert!(report1.failures.is_empty());
        assert!(list_all_cache_entries(&cache_dir).unwrap().is_empty());

        // Revoker 2 completes remote deletion (404 already inactive) and finds the record missing locally
        let report2 = process_revocation_batch(&client, &config(true), &store, batch2, now);
        assert_eq!(
            report2.remotely_inactive, 0,
            "must not increment success count on missing finalization"
        );
        assert_eq!(report2.local_only, 0);
        assert_eq!(
            report2.retained, 0,
            "missing record must not be counted as retained"
        );
        assert_eq!(report2.failures.len(), 1);
        assert!(matches!(
            report2.failures.as_slice(),
            [RevokeFailure::DeletedRecordMissing {
                remotely_revoked: true,
                ..
            }]
        ));
        assert_eq!(client.calls.get(), 2);
    }

    struct PostUnlinkSyncFailingStore {
        inner: CacheStore,
        cache_dir: std::path::PathBuf,
    }

    impl BeginRevocation for PostUnlinkSyncFailingStore {
        type Error = crate::cache::CacheError;

        fn begin_revocation(
            &self,
            selection: crate::token::store::RevocationSelection<'_>,
        ) -> Result<RevocationBatch, Self::Error> {
            self.inner.begin_revocation(selection)
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
    fn post_unlink_directory_sync_failure_reports_durability_uncertainty_without_retention() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        cache_base(&cache_dir, now + Duration::hours(1));

        let store = PostUnlinkSyncFailingStore {
            inner: CacheStore::new(&cache_dir),
            cache_dir: cache_dir.clone(),
        };
        let client = MockClient(Cell::new(0));
        let report = revoke_all(&client, &config(true), &store, now).unwrap();

        // 1. No success count
        assert_eq!(report.remotely_inactive, 0);
        assert_eq!(report.local_only, 0);

        // 2. Not counted as retained (file has already been unlinked)
        assert_eq!(report.retained, 0);

        // 3. Accurate partial outcome: DirectorySyncFailed with source error and remote revocation status
        assert_eq!(report.failures.len(), 1);
        assert!(matches!(
            report.failures.as_slice(),
            [RevokeFailure::DirectorySyncFailed {
                remotely_revoked: true,
                ..
            }]
        ));

        // 4. File was unlinked from disk
        assert!(list_all_cache_entries(&cache_dir).unwrap().is_empty());
    }
}
