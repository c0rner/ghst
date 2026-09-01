use super::{TokenError, base_cache_key, revoke_with_context};
use crate::cache::{
    AccessToken, CacheEntry, CacheError, RUN_CACHE_SCHEMA_VERSION, RunCacheEntry, RunState,
    SaveCacheEntry, cache_epoch, compute_run_cache_key, save_cache_candidate,
};
use crate::config::Config;
use crate::repository::RepositoryError;
use crate::token::{RevokeTokenClient, ScopedTokenClient};
use std::fmt::Write as _;
use std::path::Path;
use time::OffsetDateTime;

pub struct MintRunRequest<'a> {
    pub config: &'a Config,
    pub cache_dir: &'a Path,
    pub profile_name: &'a str,
    pub repositories: &'a [String],
    pub wrapper_pid: u32,
    pub command: &'a str,
}

struct RunIdentity {
    cache_key: String,
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

pub struct ActivateRunError {
    source: CacheError,
    pending: Box<PendingRun>,
}

impl std::fmt::Debug for PendingRun {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingRun")
            .field("cache_key", &self.identity.cache_key)
            .field("run_id", &self.identity.run_id)
            .field("wrapper_pid", &self.identity.wrapper_pid)
            .field("access_token", &self.access_token)
            .finish()
    }
}

impl std::fmt::Debug for ActivateRunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActivateRunError")
            .field("source", &self.source)
            .field("pending", &self.pending)
            .finish()
    }
}

impl std::fmt::Display for ActivateRunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "failed to activate run: {}", self.source)
    }
}

impl std::error::Error for ActivateRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl ActivateRunError {
    pub fn into_parts(self) -> (CacheError, PendingRun) {
        (self.source, *self.pending)
    }
}

impl PendingRun {
    pub fn access_token(&self) -> &str {
        self.access_token.as_ref()
    }

    pub fn activate(self, cache_dir: &Path, child_pid: u32) -> Result<ActiveRun, ActivateRunError> {
        match crate::cache::run_storage::activate(
            cache_dir,
            &self.identity.cache_key,
            &self.identity.run_id,
            self.identity.wrapper_pid,
            child_pid,
        ) {
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

    pub fn abort<C: RevokeTokenClient>(
        self,
        client: &C,
        config: &Config,
        cache_dir: &Path,
        child_pid: Option<u32>,
    ) -> Result<super::cleanup::CleanupReport, CacheError> {
        let entry = crate::cache::run_storage::abort(
            cache_dir,
            &self.identity.cache_key,
            &self.identity.run_id,
            self.identity.wrapper_pid,
            child_pid,
        )?;
        Ok(super::cleanup::cleanup_marked_run(
            client,
            config,
            cache_dir,
            &self.identity.cache_key,
            &entry,
        ))
    }
}

impl ActiveRun {
    pub fn finish<C: RevokeTokenClient>(
        self,
        client: &C,
        config: &Config,
        cache_dir: &Path,
    ) -> Result<super::cleanup::CleanupReport, CacheError> {
        let entry = crate::cache::run_storage::finish(
            cache_dir,
            &self.identity.cache_key,
            &self.identity.run_id,
            self.identity.wrapper_pid,
            self.child_pid,
        )?;
        Ok(super::cleanup::cleanup_marked_run(
            client,
            config,
            cache_dir,
            &self.identity.cache_key,
            &entry,
        ))
    }
}

pub fn mint<C: ScopedTokenClient>(
    client: &C,
    request: &MintRunRequest<'_>,
    resolve_auto: impl FnMut() -> Result<String, RepositoryError>,
) -> Result<PendingRun, TokenError> {
    mint_with_clock(client, request, resolve_auto, OffsetDateTime::now_utc)
}

fn mint_with_clock<
    C: ScopedTokenClient,
    R: FnMut() -> Result<String, RepositoryError>,
    N: FnMut() -> OffsetDateTime,
>(
    client: &C,
    request: &MintRunRequest<'_>,
    resolve_auto: R,
    mut now: N,
) -> Result<PendingRun, TokenError> {
    let prepared = super::scoped::prepare(
        request.config,
        request.cache_dir,
        request.profile_name,
        request.repositories,
        resolve_auto,
    )?;
    tracing::debug!(
        profile = request.profile_name,
        source_profile = prepared.profile.source,
        repo_scope = prepared.scope,
        wrapper_pid = request.wrapper_pid,
        "prepared fresh run token request"
    );
    let run_id = generate_run_id()?;
    let cache_key = compute_run_cache_key(&run_id);
    let epoch = cache_epoch(request.cache_dir)?;
    let generation = prepared.base.generation_fingerprint();
    let request_time = now();
    let issued =
        super::scoped::issue(client, &prepared, request.cache_dir, request_time, &mut now)?;
    tracing::debug!(profile = request.profile_name, expires_at = %issued.expires_at, "received valid run token from GitHub");
    let candidate = CacheEntry::Run(RunCacheEntry {
        version: RUN_CACHE_SCHEMA_VERSION,
        run_id: run_id.clone(),
        state: RunState::Pending,
        wrapper_pid: request.wrapper_pid,
        child_pid: None,
        command: request.command.to_owned(),
        profile: request.profile_name.to_owned(),
        source_profile: prepared.profile.source.clone(),
        source_authority_fingerprint: crate::cache::authority_fingerprint(
            &prepared.source.github_app.client_id,
            &prepared.source.github_app.account,
        ),
        github_user: prepared.base.github_user,
        repo_scope: prepared.scope,
        expires_at: issued.expires_at,
        access_token: issued.access_token,
    });
    let saved = save_cache_candidate(
        request.cache_dir,
        &cache_key,
        &candidate,
        epoch,
        Some((&base_cache_key(&prepared.profile.source), &generation)),
    );
    match saved {
        Ok(SaveCacheEntry::Saved) => {
            let CacheEntry::Run(entry) = candidate else {
                unreachable!("run candidate changed kind")
            };
            tracing::debug!(
                profile = request.profile_name,
                cache_key,
                run_id,
                "persisted pending run recovery entry"
            );
            Ok(PendingRun {
                identity: RunIdentity {
                    cache_key,
                    run_id,
                    wrapper_pid: request.wrapper_pid,
                },
                access_token: entry.access_token,
            })
        }
        Ok(SaveCacheEntry::Retained(_)) => unreachable!("run entries are never reusable"),
        Err(source_error) => {
            tracing::debug!(profile = request.profile_name, error = %source_error, "failed to persist pending run recovery entry; revoking candidate");
            Err(revoke_with_context(
                client,
                prepared.source,
                candidate.access_token(),
                TokenError::Cache(source_error),
            ))
        }
    }
}

fn generate_run_id() -> Result<String, TokenError> {
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
        BaseCacheEntry, CACHE_SCHEMA_VERSION, ScopedCacheEntry, TokenExpiry, authority_fingerprint,
        compute_cache_key, compute_run_cache_key, policy_fingerprint, save_cache_entry,
    };
    use crate::github::GitHubError;
    use crate::token::{IssuedScopedToken, RevokeTokenClient, ScopedTokenRequest};
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use time::Duration;

    struct MockClient(Cell<usize>);

    impl RevokeTokenClient for MockClient {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            _access_token: &str,
        ) -> Result<(), GitHubError> {
            Ok(())
        }
    }

    impl ScopedTokenClient for MockClient {
        fn create_scoped_token(
            &self,
            _request: &ScopedTokenRequest<'_>,
        ) -> Result<IssuedScopedToken, GitHubError> {
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
        ) -> Result<(), GitHubError> {
            if let Some((cache_dir, cache_key)) = &self.cache_entry {
                let CacheEntry::Run(entry) = crate::cache::load_cache_entry(cache_dir, cache_key)
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
                Err(GitHubError::Http {
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
            &CacheEntry::Base(BaseCacheEntry {
                version: CACHE_SCHEMA_VERSION,
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
            &CacheEntry::Run(RunCacheEntry {
                version: RUN_CACHE_SCHEMA_VERSION,
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
                cache_key,
                run_id: run_id.into(),
                wrapper_pid: 100,
            },
            access_token: format!("token-{run_id}").into(),
        }
    }

    #[test]
    fn run_ids_are_unique_random_and_domain_separated() {
        let first = generate_run_id().unwrap();
        let second = generate_run_id().unwrap();
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
        let config = config();
        cache_base(&cache_dir, now);
        let permissions = BTreeMap::from([("contents".into(), String::from("read"))]);
        save_cache_entry(
            &cache_dir,
            &compute_cache_key("reader", "acme/api"),
            &CacheEntry::Scoped(ScopedCacheEntry {
                version: CACHE_SCHEMA_VERSION,
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
                    CacheEntry::Base(entry) => entry.generation_fingerprint(),
                    CacheEntry::Scoped(_) | CacheEntry::Run(_) => panic!("expected base"),
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
        let request = MintRunRequest {
            config: &config,
            cache_dir: &cache_dir,
            profile_name: "reader",
            repositories: &[],
            wrapper_pid: std::process::id(),
            command: "true",
        };
        let first = mint(&client, &request, || panic!("auto is not used")).unwrap();
        let second = mint(&client, &request, || panic!("auto is not used")).unwrap();
        assert_eq!(first.access_token(), "fresh-1");
        assert_eq!(second.access_token(), "fresh-2");
        assert_ne!(first.identity.cache_key, second.identity.cache_key);
        assert_eq!(client.0.get(), 2);
    }

    #[test]
    fn activation_persists_the_exact_child_owner() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let pending = pending_run(&cache_dir, "activate");
        let cache_key = pending.identity.cache_key.clone();

        let active = pending.activate(&cache_dir, 200).unwrap();

        assert_eq!(active.child_pid, 200);
        assert!(matches!(
            crate::cache::load_cache_entry(&cache_dir, &cache_key).unwrap(),
            Some(CacheEntry::Run(RunCacheEntry {
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
        let cache_key = pending.identity.cache_key.clone();
        let client = LifecycleClient::observing(&cache_dir, &cache_key);

        let report = pending.abort(&client, &config(), &cache_dir, None).unwrap();

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
        let cache_key = pending.identity.cache_key.clone();
        let client = LifecycleClient::observing(&cache_dir, &cache_key);
        client.fail.set(true);

        let report = pending
            .abort(&client, &config(), &cache_dir, Some(201))
            .unwrap();

        assert!(!report.is_complete());
        assert_eq!(
            &*client.observed_states.borrow(),
            &[(RunState::CleanupPending, Some(201))]
        );
        assert!(matches!(
            crate::cache::load_cache_entry(&cache_dir, &cache_key).unwrap(),
            Some(CacheEntry::Run(RunCacheEntry {
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
        let cache_key = pending.identity.cache_key.clone();
        let active = pending.activate(&cache_dir, 202).unwrap();
        let client = LifecycleClient::observing(&cache_dir, &cache_key);

        let report = active.finish(&client, &config(), &cache_dir).unwrap();

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

        let Err(error) = pending.activate(&cache_dir, 203) else {
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
        let cache_key = pending.identity.cache_key.clone();
        let active = pending.activate(&cache_dir, 204).unwrap();
        let client = LifecycleClient::observing(&cache_dir, &cache_key);
        client.fail.set(true);

        let report = active.finish(&client, &config(), &cache_dir).unwrap();

        assert!(!report.is_complete());
        assert!(matches!(
            crate::cache::load_cache_entry(&cache_dir, &cache_key).unwrap(),
            Some(CacheEntry::Run(RunCacheEntry {
                state: RunState::CleanupPending,
                ..
            }))
        ));

        client.fail.set(false);
        let report =
            super::super::cleanup::prune(&client, &config(), &cache_dir, OffsetDateTime::now_utc())
                .unwrap();
        assert!(report.is_complete());
        assert!(
            crate::cache::load_cache_entry(&cache_dir, &cache_key)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn run_rejects_app_profiles_before_minting() {
        let temp = tempfile::tempdir().unwrap();
        let config = config();
        let client = MockClient(Cell::new(0));
        let result = mint(
            &client,
            &MintRunRequest {
                config: &config,
                cache_dir: temp.path(),
                profile_name: "developer",
                repositories: &[],
                wrapper_pid: std::process::id(),
                command: "true",
            },
            || panic!("auto is not used"),
        );
        assert!(matches!(result, Err(TokenError::RunRequiresScoped(_))));
        assert_eq!(client.0.get(), 0);
    }
}
