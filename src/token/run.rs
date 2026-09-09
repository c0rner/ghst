use std::collections::BTreeMap;
use std::fmt::Write as _;
use time::OffsetDateTime;

use super::{TokenError, revoke_with_context};
use crate::config::Config;
use crate::credential::store::{
    IssuanceGuardStore, ReadCredentials, SourceGuard, WriteCredentials,
};
use crate::credential::{AccessToken, authority_fingerprint};
use crate::domain::profile::{AppCredentials, PermissionLevel};
use crate::repository::RepositorySelection;
use crate::run::store::{PendingRunOutcome, PendingRunStore, RunLifecycleStore};
use crate::run::{RunRecord, RunState};
use crate::token::{RevokeTokenClient, ScopedTokenClient};

pub struct MintRunRequest<'a> {
    pub profile_name: &'a str,
    pub source_name: &'a str,
    pub app: AppCredentials<'a>,
    pub permissions: &'a BTreeMap<String, PermissionLevel>,
    pub repositories: RepositorySelection,
    pub wrapper_pid: u32,
    pub command: &'a str,
}

struct RunIdentity {
    run_id: String,
    wrapper_pid: u32,
}

pub struct PendingRun {
    identity: RunIdentity,
    access_token: AccessToken,
}

pub struct ActiveRun {
    identity: RunIdentity,
    child_pid: u32,
}

pub struct ActivateRunError<E> {
    source: E,
    pending: Box<PendingRun>,
}

impl std::fmt::Debug for PendingRun {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingRun")
            .field("run_id", &self.identity.run_id)
            .field("wrapper_pid", &self.identity.wrapper_pid)
            .field("access_token", &self.access_token)
            .finish()
    }
}

impl<E: std::fmt::Debug> std::fmt::Debug for ActivateRunError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActivateRunError")
            .field("source", &self.source)
            .field("pending", &self.pending)
            .finish()
    }
}

impl<E: std::fmt::Display> std::fmt::Display for ActivateRunError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "failed to activate run: {}", self.source)
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ActivateRunError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl<E> ActivateRunError<E> {
    pub fn into_parts(self) -> (E, PendingRun) {
        (self.source, *self.pending)
    }
}

impl PendingRun {
    pub fn access_token(&self) -> &str {
        self.access_token.as_ref()
    }

    pub fn activate<S, E>(self, store: &S, child_pid: u32) -> Result<ActiveRun, ActivateRunError<E>>
    where
        S: RunLifecycleStore<Error = E>,
    {
        match store.activate(&self.identity.run_id, self.identity.wrapper_pid, child_pid) {
            Ok(_) => Ok(ActiveRun {
                identity: self.identity,
                child_pid,
            }),
            Err(source) => Err(ActivateRunError {
                source,
                pending: Box::new(self),
            }),
        }
    }

    pub fn abort<C, S, E>(
        self,
        client: &C,
        config: &Config,
        store: &S,
        child_pid: Option<u32>,
    ) -> Result<super::cleanup::CleanupReport<E>, E>
    where
        C: RevokeTokenClient,
        S: RunLifecycleStore<Error = E>,
        E: std::fmt::Debug + std::fmt::Display,
    {
        let entry = store.abort(&self.identity.run_id, self.identity.wrapper_pid, child_pid)?;
        Ok(super::cleanup::cleanup_marked_run(
            client, config, store, &entry,
        ))
    }
}

impl ActiveRun {
    pub fn finish<C, S, E>(
        self,
        client: &C,
        config: &Config,
        store: &S,
    ) -> Result<super::cleanup::CleanupReport<E>, E>
    where
        C: RevokeTokenClient,
        S: RunLifecycleStore<Error = E>,
        E: std::fmt::Debug + std::fmt::Display,
    {
        let entry = store.finish(
            &self.identity.run_id,
            self.identity.wrapper_pid,
            self.child_pid,
        )?;
        Ok(super::cleanup::cleanup_marked_run(
            client, config, store, &entry,
        ))
    }
}

pub fn mint<C, S, E>(
    client: &C,
    store: &S,
    request: &MintRunRequest<'_>,
) -> Result<PendingRun, TokenError<E>>
where
    C: ScopedTokenClient,
    S: ReadCredentials<Error = E>
        + WriteCredentials<Error = E>
        + IssuanceGuardStore<Error = E>
        + PendingRunStore<Error = E>,
    E: std::error::Error + 'static,
{
    mint_with_clock(client, store, request, OffsetDateTime::now_utc)
}

fn mint_with_clock<C, S, E, N>(
    client: &C,
    store: &S,
    request: &MintRunRequest<'_>,
    mut now: N,
) -> Result<PendingRun, TokenError<E>>
where
    C: ScopedTokenClient,
    S: ReadCredentials<Error = E>
        + WriteCredentials<Error = E>
        + IssuanceGuardStore<Error = E>
        + PendingRunStore<Error = E>,
    E: std::error::Error + 'static,
    N: FnMut() -> OffsetDateTime,
{
    let prepared = super::scoped::prepare(
        store,
        request.profile_name,
        request.source_name,
        request.app,
        request.permissions,
        &request.repositories,
    )?;
    tracing::debug!(
        profile = prepared.profile_name,
        source_profile = prepared.source_name,
        repo_scope = prepared.scope,
        wrapper_pid = request.wrapper_pid,
        "prepared fresh run token request"
    );
    let run_id = generate_run_id()?;
    let guard = store.issuance_guard().map_err(TokenError::Storage)?;
    let expected_generation = prepared.base.generation_fingerprint();
    let source_guard = SourceGuard {
        source_profile: prepared.source_name,
        expected_generation: &expected_generation,
    };
    let request_time = now();
    let issued = super::scoped::issue(client, store, &prepared, request_time, &mut now)?;
    tracing::debug!(
        profile = prepared.profile_name,
        expires_at = %issued.expires_at,
        "received valid run token from GitHub"
    );
    let candidate = RunRecord {
        run_id,
        state: RunState::Pending,
        wrapper_pid: request.wrapper_pid,
        child_pid: None,
        command: request.command.to_owned(),
        profile: prepared.profile_name.to_owned(),
        source_profile: prepared.source_name.to_owned(),
        source_authority_fingerprint: authority_fingerprint(
            prepared.app.authority.client_id,
            prepared.app.authority.account,
        ),
        github_user: prepared.base.github_user,
        repo_scope: prepared.scope,
        expires_at: issued.expires_at,
        access_token: issued.access_token,
    };
    let outcome = match store.commit_pending(&candidate, guard, &source_guard) {
        Ok(outcome) => outcome,
        Err(source_error) => {
            tracing::debug!(
                profile = prepared.profile_name,
                error = %source_error,
                "failed to persist pending run recovery entry; revoking candidate"
            );
            return Err(revoke_with_context(
                client,
                &prepared.app.as_registration(),
                &candidate.access_token,
                TokenError::Storage(source_error),
            ));
        }
    };
    handle_pending_outcome(
        client,
        &prepared.app.as_registration(),
        prepared.profile_name,
        candidate,
        outcome,
    )
}

fn handle_pending_outcome<C: RevokeTokenClient + ?Sized, E>(
    client: &C,
    app: &crate::domain::profile::AppRegistration<'_>,
    profile_name: &str,
    candidate: RunRecord,
    outcome: PendingRunOutcome,
) -> Result<PendingRun, TokenError<E>> {
    match outcome {
        PendingRunOutcome::Saved => {
            tracing::debug!(
                profile = profile_name,
                run_id = candidate.run_id,
                "persisted pending run recovery entry"
            );
            Ok(PendingRun {
                identity: RunIdentity {
                    run_id: candidate.run_id,
                    wrapper_pid: candidate.wrapper_pid,
                },
                access_token: candidate.access_token,
            })
        }
        PendingRunOutcome::EpochChanged => {
            tracing::debug!(
                profile = profile_name,
                run_id = candidate.run_id,
                "cache epoch changed during run issuance; revoking candidate"
            );
            Err(revoke_with_context(
                client,
                app,
                &candidate.access_token,
                TokenError::EpochChanged(profile_name.to_owned()),
            ))
        }
        PendingRunOutcome::BaseGenerationChanged => {
            tracing::debug!(
                profile = profile_name,
                run_id = candidate.run_id,
                "source base generation changed during run issuance; revoking candidate"
            );
            Err(revoke_with_context(
                client,
                app,
                &candidate.access_token,
                TokenError::BaseGenerationChanged(profile_name.to_owned()),
            ))
        }
    }
}

fn generate_run_id<E>() -> Result<String, TokenError<E>> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random)?;
    let mut encoded = String::with_capacity(64);
    for byte in random {
        let _ = write!(encoded, "{byte:02x}");
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{
        CacheError, CacheStore, Record, compute_cache_key, compute_run_cache_key, save_cache_entry,
    };
    use crate::credential::{
        BaseCredential, ScopedCredential, TokenExpiry, authority_fingerprint, policy_fingerprint,
    };
    use crate::run::{RunRecord, RunState};
    use crate::token::{IssuedScopedToken, RemoteError, RevokeTokenClient, ScopedTokenRequest};
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use time::Duration;

    struct MockClient(Cell<usize>);

    impl RevokeTokenClient for MockClient {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            _access_token: &str,
        ) -> Result<(), RemoteError> {
            Ok(())
        }
    }

    impl ScopedTokenClient for MockClient {
        fn create_scoped_token(
            &self,
            _request: &ScopedTokenRequest<'_>,
        ) -> Result<IssuedScopedToken, RemoteError> {
            let number = self.0.get() + 1;
            self.0.set(number);
            Ok(IssuedScopedToken {
                access_token: format!("fresh-{number}").into(),
                expires_at: Some(
                    TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(1)).to_string(),
                ),
            })
        }
    }

    struct LifecycleClient {
        cache_entry: Option<(PathBuf, String)>,
        observed_states: RefCell<Vec<(RunState, Option<u32>)>>,
        revoked: RefCell<Vec<String>>,
        fail: Cell<bool>,
    }

    impl LifecycleClient {
        fn observing(cache_dir: &Path, cache_key: &str) -> Self {
            Self {
                cache_entry: Some((cache_dir.to_owned(), cache_key.to_owned())),
                observed_states: RefCell::new(Vec::new()),
                revoked: RefCell::new(Vec::new()),
                fail: Cell::new(false),
            }
        }
    }

    impl RevokeTokenClient for LifecycleClient {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            access_token: &str,
        ) -> Result<(), RemoteError> {
            if let Some((cache_dir, cache_key)) = &self.cache_entry {
                let Record::Run(entry) = crate::cache::load_cache_entry(cache_dir, cache_key)
                    .unwrap()
                    .unwrap()
                else {
                    panic!("expected run entry")
                };
                self.observed_states
                    .borrow_mut()
                    .push((entry.state, entry.child_pid));
            }
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

    fn cache_base(cache_dir: &Path, now: OffsetDateTime) {
        save_cache_entry(
            cache_dir,
            &compute_cache_key("developer", "all"),
            &Record::Base(BaseCredential {
                profile: "developer".into(),
                authority_fingerprint: authority_fingerprint("id", "acme"),
                github_user: "octocat".into(),
                expires_at: TokenExpiry::new(now + Duration::hours(1)),
                access_token: "base".into(),
            }),
        )
        .unwrap();
    }

    fn pending_run(cache_dir: &Path, run_id: &str) -> PendingRun {
        let cache_key = compute_run_cache_key(run_id);
        save_cache_entry(
            cache_dir,
            &cache_key,
            &Record::Run(RunRecord {
                run_id: run_id.into(),
                state: RunState::Pending,
                wrapper_pid: 100,
                child_pid: None,
                command: "true".into(),
                profile: "reader".into(),
                source_profile: "developer".into(),
                source_authority_fingerprint: authority_fingerprint("id", "acme"),
                github_user: "octocat".into(),
                repo_scope: "acme/api".into(),
                expires_at: TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(1)),
                access_token: format!("token-{run_id}").into(),
            }),
        )
        .unwrap();
        PendingRun {
            identity: RunIdentity {
                run_id: run_id.into(),
                wrapper_pid: 100,
            },
            access_token: format!("token-{run_id}").into(),
        }
    }

    #[test]
    fn run_ids_are_unique_random_and_domain_separated() {
        let first = generate_run_id::<CacheError>().unwrap();
        let second = generate_run_id::<CacheError>().unwrap();
        assert_eq!(first.len(), 64);
        assert_ne!(first, second);
        assert_ne!(
            compute_run_cache_key(&first),
            compute_cache_key("run", &first)
        );
    }

    #[test]
    fn each_run_mints_fresh_despite_a_reusable_scoped_token() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        cache_base(&cache_dir, now);
        let permissions = BTreeMap::from([("contents".into(), String::from("read"))]);
        save_cache_entry(
            &cache_dir,
            &compute_cache_key("reader", "acme/api"),
            &Record::Scoped(ScopedCredential {
                profile: "reader".into(),
                source_profile: "developer".into(),
                source_authority_fingerprint: authority_fingerprint("id", "acme"),
                parent_generation: match crate::cache::load_cache_entry(
                    &cache_dir,
                    &compute_cache_key("developer", "all"),
                )
                .unwrap()
                .unwrap()
                {
                    Record::Base(entry) => entry.generation_fingerprint(),
                    Record::Scoped(_) | Record::Run(_) => panic!("expected base"),
                },
                policy_fingerprint: policy_fingerprint("acme", "acme/api", &permissions),
                github_user: "octocat".into(),
                repo_scope: "acme/api".into(),
                expires_at: TokenExpiry::new(now + Duration::hours(1)),
                access_token: "reusable".into(),
            }),
        )
        .unwrap();
        let client = MockClient(Cell::new(0));
        let app = AppCredentials {
            authority: crate::domain::profile::AppAuthority {
                account: "acme",
                client_id: "id",
            },
            client_secret: "secret",
        };
        let scoped_permissions = BTreeMap::from([("contents".into(), PermissionLevel::Read)]);
        let store = CacheStore::new(&cache_dir);
        let request = MintRunRequest {
            profile_name: "reader",
            source_name: "developer",
            app,
            permissions: &scoped_permissions,
            repositories: RepositorySelection::resolve(
                &["acme/api".into()],
                &crate::domain::profile::RepoScope::All,
                "acme",
                || panic!("auto is not used"),
            )
            .unwrap(),
            wrapper_pid: std::process::id(),
            command: "true",
        };
        let first = mint(&client, &store, &request).unwrap();
        let second = mint(&client, &store, &request).unwrap();
        assert_eq!(first.access_token(), "fresh-1");
        assert_eq!(second.access_token(), "fresh-2");
        assert_ne!(first.identity.run_id, second.identity.run_id);
        assert_eq!(client.0.get(), 2);
    }

    #[test]
    fn activation_persists_the_exact_child_owner() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let pending = pending_run(&cache_dir, "activate");
        let cache_key = compute_run_cache_key(&pending.identity.run_id);
        let store = CacheStore::new(&cache_dir);

        let active = pending.activate(&store, 200).unwrap();

        assert_eq!(active.child_pid, 200);
        assert!(matches!(
            crate::cache::load_cache_entry(&cache_dir, &cache_key).unwrap(),
            Some(Record::Run(RunRecord {
                state: RunState::Running,
                child_pid: Some(200),
                ..
            }))
        ));
    }

    #[test]
    fn abort_before_spawn_marks_without_a_child_then_revokes_and_deletes() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let pending = pending_run(&cache_dir, "abort-before-spawn");
        let cache_key = compute_run_cache_key(&pending.identity.run_id);
        let client = LifecycleClient::observing(&cache_dir, &cache_key);
        let store = CacheStore::new(&cache_dir);

        let report = pending.abort(&client, &config(), &store, None).unwrap();

        assert!(report.is_complete());
        assert_eq!(
            &*client.observed_states.borrow(),
            &[(RunState::CleanupPending, None)]
        );
        assert_eq!(&*client.revoked.borrow(), &["token-abort-before-spawn"]);
        assert!(
            crate::cache::load_cache_entry(&cache_dir, &cache_key)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn abort_after_spawn_records_the_child_before_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let pending = pending_run(&cache_dir, "abort-after-spawn");
        let cache_key = compute_run_cache_key(&pending.identity.run_id);
        let client = LifecycleClient::observing(&cache_dir, &cache_key);
        client.fail.set(true);
        let store = CacheStore::new(&cache_dir);

        let report = pending
            .abort(&client, &config(), &store, Some(201))
            .unwrap();

        assert!(!report.is_complete());
        assert_eq!(
            &*client.observed_states.borrow(),
            &[(RunState::CleanupPending, Some(201))]
        );
        assert!(matches!(
            crate::cache::load_cache_entry(&cache_dir, &cache_key).unwrap(),
            Some(Record::Run(RunRecord {
                state: RunState::CleanupPending,
                child_pid: Some(201),
                ..
            }))
        ));
    }

    #[test]
    fn finish_claims_revokes_and_deletes_the_exact_active_run() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let pending = pending_run(&cache_dir, "finish");
        let cache_key = compute_run_cache_key(&pending.identity.run_id);
        let store = CacheStore::new(&cache_dir);
        let active = pending.activate(&store, 202).unwrap();
        let client = LifecycleClient::observing(&cache_dir, &cache_key);

        let report = active.finish(&client, &config(), &store).unwrap();

        assert!(report.is_complete());
        assert_eq!(
            &*client.observed_states.borrow(),
            &[(RunState::CleanupPending, Some(202))]
        );
        assert_eq!(&*client.revoked.borrow(), &["token-finish"]);
        assert!(
            crate::cache::load_cache_entry(&cache_dir, &cache_key)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn activation_failure_returns_the_cache_error_and_pending_run_without_exposing_its_token() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let mut pending = pending_run(&cache_dir, "owned");
        pending.identity.run_id = "wrong-owner".into();
        let store = CacheStore::new(&cache_dir);

        let Err(error) = pending.activate(&store, 203) else {
            panic!("mismatched owner unexpectedly activated")
        };
        let debug = format!("{error:?}");
        assert!(!debug.contains("token-owned"));
        assert!(debug.contains("[REDACTED]"));
        let (source, recovered) = error.into_parts();
        assert!(matches!(source, CacheError::InvalidRunTransition(_)));
        assert_eq!(recovered.access_token(), "token-owned");
    }

    #[test]
    fn failed_finish_retains_cleanup_pending_for_a_later_prune() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let pending = pending_run(&cache_dir, "retry");
        let cache_key = compute_run_cache_key(&pending.identity.run_id);
        let store = CacheStore::new(&cache_dir);
        let active = pending.activate(&store, 204).unwrap();
        let client = LifecycleClient::observing(&cache_dir, &cache_key);
        client.fail.set(true);

        let report = active.finish(&client, &config(), &store).unwrap();

        assert!(!report.is_complete());
        assert!(matches!(
            crate::cache::load_cache_entry(&cache_dir, &cache_key).unwrap(),
            Some(Record::Run(RunRecord {
                state: RunState::CleanupPending,
                ..
            }))
        ));

        client.fail.set(false);
        let report =
            super::super::cleanup::prune(&client, &config(), &store, OffsetDateTime::now_utc())
                .unwrap();
        assert!(report.is_complete());
        assert!(
            crate::cache::load_cache_entry(&cache_dir, &cache_key)
                .unwrap()
                .is_none()
        );
    }
}
