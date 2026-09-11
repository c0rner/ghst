use std::fmt;

use crate::credential::authority_fingerprint;
use crate::profile::{AppCredentials, NamedAppRegistration};
use crate::run::store::RunLifecycleStore;
use crate::run::{RunRecord, RunState};
use crate::token::{RemoteError, RevokeTokenClient};

/// Failure encountered during marked run cleanup or cache pruning.
pub enum CleanupFailure<E> {
    InvalidEntry { entry: String },
    Configuration { entry: String },
    ClientSecretUnavailable { entry: String },
    Ownership { entry: String, source: E },
    GitHubRevocation { entry: String, source: RemoteError },
    CacheDeletion { entry: String, source: E },
    DirectorySyncFailed { entry: String, source: E },
}

impl<E: fmt::Debug> fmt::Debug for CleanupFailure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEntry { entry } => f
                .debug_struct("InvalidEntry")
                .field("entry", entry)
                .finish(),
            Self::Configuration { entry } => f
                .debug_struct("Configuration")
                .field("entry", entry)
                .finish(),
            Self::ClientSecretUnavailable { entry } => f
                .debug_struct("ClientSecretUnavailable")
                .field("entry", entry)
                .finish(),
            Self::Ownership { entry, source } => f
                .debug_struct("Ownership")
                .field("entry", entry)
                .field("source", source)
                .finish(),
            Self::GitHubRevocation { entry, source } => f
                .debug_struct("GitHubRevocation")
                .field("entry", entry)
                .field("source_kind", &source.kind())
                .finish(),
            Self::CacheDeletion { entry, source } => f
                .debug_struct("CacheDeletion")
                .field("entry", entry)
                .field("source", source)
                .finish(),
            Self::DirectorySyncFailed { entry, source } => f
                .debug_struct("DirectorySyncFailed")
                .field("entry", entry)
                .field("source", source)
                .finish(),
        }
    }
}

/// Outcome of processing an individual candidate record for cleanup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupOutcome {
    NoAction,
    ExpiredDeleted,
    RunRevoked,
    ActiveRunSkipped,
}

pub type CleanupAttempt<E> = Result<CleanupOutcome, CleanupFailure<E>>;

/// Aggregated report of cleanup and prune operations.
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

impl<E: fmt::Debug> CleanupReport<E> {
    pub const fn is_complete(&self) -> bool {
        self.retained_entries == 0 && self.failures.is_empty()
    }

    pub fn record(&mut self, attempt: CleanupAttempt<E>) {
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

/// Cleans up a marked run using the exact `AppCredentials` from the foreground request.
pub fn cleanup_marked_run_with_app<C, S, E>(
    client: &C,
    app: &AppCredentials<'_>,
    source_name: &str,
    store: &S,
    entry: &RunRecord,
) -> CleanupReport<E>
where
    C: RevokeTokenClient,
    S: RunLifecycleStore<Error = E>,
    E: fmt::Debug + fmt::Display,
{
    let mut report = CleanupReport::default();
    let attempt = cleanup_marked_entry_with_app(client, app, source_name, store, entry);
    report.record(attempt);
    report
}

fn cleanup_marked_entry_with_app<C, S, E>(
    client: &C,
    app: &AppCredentials<'_>,
    source_name: &str,
    store: &S,
    entry: &RunRecord,
) -> CleanupAttempt<E>
where
    C: RevokeTokenClient,
    S: RunLifecycleStore<Error = E>,
    E: fmt::Display,
{
    let label = entry.run_id.clone();
    if entry.state != RunState::CleanupPending {
        tracing::debug!(
            run_id = entry.run_id,
            state = ?entry.state,
            "record must be in CleanupPending state before cleanup"
        );
        return Err(CleanupFailure::InvalidEntry { entry: label });
    }
    let expected_fp = authority_fingerprint(app.authority.client_id, app.authority.account);
    if entry.source_profile != source_name || entry.source_authority_fingerprint != expected_fp {
        tracing::debug!(
            run_id = entry.run_id,
            source_profile = entry.source_profile,
            "run token source authority does not match supplied credentials"
        );
        return Err(CleanupFailure::Configuration { entry: label });
    }
    if app.client_secret.is_empty() {
        tracing::debug!(
            run_id = entry.run_id,
            source_profile = entry.source_profile,
            "run token cannot be remotely revoked because client secret is empty"
        );
        return Err(CleanupFailure::ClientSecretUnavailable { entry: label });
    }
    match client.delete_token(
        app.authority.client_id,
        app.client_secret,
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
            tracing::debug!(
                run_id = entry.run_id,
                error = %source,
                "failed to delete run recovery entry after remote cleanup"
            );
            Err(CleanupFailure::CacheDeletion {
                entry: label,
                source,
            })
        }
    }
}

pub fn cleanup_marked_entry<C, S, E>(
    client: &C,
    apps: &[NamedAppRegistration<'_>],
    label: &str,
    entry: &RunRecord,
    store: &S,
) -> CleanupAttempt<E>
where
    C: RevokeTokenClient,
    S: RunLifecycleStore<Error = E>,
    E: fmt::Display,
{
    let label = label.to_owned();
    let Some(app) = validated_app(apps, entry) else {
        tracing::debug!(
            run_id = entry.run_id,
            source_profile = entry.source_profile,
            "run token source authority no longer matches configuration"
        );
        return Err(CleanupFailure::Configuration { entry: label });
    };
    let Some(secret) = app.client_secret else {
        tracing::debug!(
            run_id = entry.run_id,
            source_profile = entry.source_profile,
            "run token cannot be remotely revoked because the source profile has no client secret"
        );
        return Err(CleanupFailure::ClientSecretUnavailable { entry: label });
    };
    match client.delete_token(app.authority.client_id, secret, entry.access_token.as_ref()) {
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

fn validated_app<'a>(
    apps: &[NamedAppRegistration<'a>],
    entry: &RunRecord,
) -> Option<crate::profile::AppRegistration<'a>> {
    match crate::token::provenance::for_source(
        apps,
        &entry.source_profile,
        &entry.source_authority_fingerprint,
    ) {
        crate::token::provenance::ConfiguredAuthority::Match(app) => Some(app),
        crate::token::provenance::ConfiguredAuthority::Mismatch
        | crate::token::provenance::ConfiguredAuthority::Missing => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{AccessToken, TokenExpiry};
    use crate::profile::AppAuthority;
    use crate::token::RemoteError;
    use std::cell::RefCell;

    #[derive(Debug)]
    struct MockError;

    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "mock error")
        }
    }

    impl std::error::Error for MockError {}

    struct FakeClient {
        deleted: RefCell<Vec<String>>,
        result: Option<Result<(), RemoteError>>,
    }

    impl FakeClient {
        fn new(result: Option<Result<(), RemoteError>>) -> Self {
            Self {
                deleted: RefCell::new(Vec::new()),
                result,
            }
        }
    }

    impl RevokeTokenClient for FakeClient {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            access_token: &str,
        ) -> Result<(), RemoteError> {
            self.deleted.borrow_mut().push(access_token.to_string());
            match &self.result {
                Some(Ok(())) | None => Ok(()),
                Some(Err(err)) => Err(RemoteError::Http {
                    status: match err {
                        RemoteError::Http { status, .. } => *status,
                        _ => 500,
                    },
                    message: "error".into(),
                }),
            }
        }
    }

    struct FakeLifecycleStore {
        deleted: RefCell<Vec<String>>,
    }

    impl RunLifecycleStore for FakeLifecycleStore {
        type Error = MockError;

        fn activate(
            &self,
            _run_id: &str,
            _wrapper_pid: u32,
            _child_pid: u32,
        ) -> Result<RunRecord, Self::Error> {
            unimplemented!()
        }

        fn abort(
            &self,
            _run_id: &str,
            _wrapper_pid: u32,
            _child_pid: Option<u32>,
        ) -> Result<RunRecord, Self::Error> {
            unimplemented!()
        }

        fn finish(
            &self,
            _run_id: &str,
            _wrapper_pid: u32,
            _child_pid: u32,
        ) -> Result<RunRecord, Self::Error> {
            unimplemented!()
        }

        fn claim_abandoned(&self, _expected: &RunRecord) -> Result<RunRecord, Self::Error> {
            unimplemented!()
        }

        fn delete_cleanup_pending(&self, expected: &RunRecord) -> Result<bool, Self::Error> {
            self.deleted.borrow_mut().push(expected.run_id.clone());
            Ok(true)
        }
    }

    fn sample_cleanup_record() -> RunRecord {
        RunRecord {
            run_id: "run-cleanup-1".into(),
            state: RunState::CleanupPending,
            wrapper_pid: 100,
            child_pid: Some(200),
            command: "echo test".into(),
            profile: "reader".into(),
            source_profile: "developer".into(),
            source_authority_fingerprint: authority_fingerprint("client-1", "acme"),
            github_user: "octocat".into(),
            repo_scope: "acme/repo".into(),
            expires_at: TokenExpiry::parse("2026-09-01T00:00:00Z").unwrap(),
            access_token: AccessToken::from("ghu_tok_cleanup_123"),
        }
    }

    #[test]
    fn test_cleanup_marked_run_with_app_success() {
        let client = FakeClient::new(Some(Ok(())));
        let store = FakeLifecycleStore {
            deleted: RefCell::new(Vec::new()),
        };
        let app = AppCredentials {
            authority: AppAuthority {
                account: "acme",
                client_id: "client-1",
            },
            client_secret: "secret-1",
        };
        let entry = sample_cleanup_record();

        let report = cleanup_marked_run_with_app(&client, &app, "developer", &store, &entry);
        assert!(report.is_complete());
        assert_eq!(report.revoked_runs, 1);
        assert_eq!(*client.deleted.borrow(), vec!["ghu_tok_cleanup_123"]);
        assert_eq!(*store.deleted.borrow(), vec!["run-cleanup-1"]);
    }

    #[test]
    fn test_cleanup_marked_run_with_app_authority_mismatch_fails_closed() {
        let client = FakeClient::new(Some(Ok(())));
        let store = FakeLifecycleStore {
            deleted: RefCell::new(Vec::new()),
        };
        let app = AppCredentials {
            authority: AppAuthority {
                account: "wrong-account",
                client_id: "client-1",
            },
            client_secret: "secret-1",
        };
        let entry = sample_cleanup_record();

        let report = cleanup_marked_run_with_app(&client, &app, "developer", &store, &entry);
        assert!(!report.is_complete());
        assert_eq!(report.retained_entries, 1);
        assert!(client.deleted.borrow().is_empty());
        assert!(store.deleted.borrow().is_empty());
    }
}
