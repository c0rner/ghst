use super::{TokenError, revoke_with_context, root_cache_key};
use crate::cache::{
    CacheEntry, RUN_CACHE_SCHEMA_VERSION, RunCacheEntry, RunState, SaveCacheEntry, cache_epoch,
    compute_run_cache_key, save_cache_candidate,
};
use crate::config::Config;
use crate::repository::RepositoryError;
use crate::token::ScopedTokenClient;
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

pub struct PendingRun {
    pub cache_key: String,
    pub run_id: String,
    pub wrapper_pid: u32,
    pub access_token: crate::cache::AccessToken,
}

impl std::fmt::Debug for PendingRun {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingRun")
            .field("cache_key", &self.cache_key)
            .field("run_id", &self.run_id)
            .field("wrapper_pid", &self.wrapper_pid)
            .field("access_token", &self.access_token)
            .finish()
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
    let generation = prepared.root.generation_fingerprint();
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
        github_user: prepared.root.github_user,
        repo_scope: prepared.scope,
        expires_at: issued.expires_at,
        access_token: issued.access_token,
    });
    let saved = save_cache_candidate(
        request.cache_dir,
        &cache_key,
        &candidate,
        epoch,
        Some((&root_cache_key(&prepared.profile.source), &generation)),
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
                cache_key,
                run_id,
                wrapper_pid: request.wrapper_pid,
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
        CACHE_SCHEMA_VERSION, DerivedCacheEntry, RootCacheEntry, TokenExpiry,
        authority_fingerprint, compute_cache_key, compute_run_cache_key, policy_fingerprint,
        save_cache_entry,
    };
    use crate::github::GitHubError;
    use crate::token::{IssuedScopedToken, RevokeTokenClient, ScopedTokenRequest};
    use std::cell::Cell;
    use std::collections::BTreeMap;
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

    fn cache_root(cache_dir: &Path, now: OffsetDateTime) {
        save_cache_entry(
            cache_dir,
            &compute_cache_key("developer", "all"),
            &CacheEntry::Root(RootCacheEntry {
                version: CACHE_SCHEMA_VERSION,
                profile: "developer".into(),
                authority_fingerprint: authority_fingerprint("id", "acme"),
                github_user: "octocat".into(),
                expires_at: TokenExpiry::new(now + Duration::hours(1)),
                access_token: "root".into(),
            }),
        )
        .unwrap();
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
    fn each_run_mints_fresh_despite_a_reusable_derived_token() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        let config = config();
        cache_root(&cache_dir, now);
        let permissions = BTreeMap::from([("contents".into(), "read".into())]);
        save_cache_entry(
            &cache_dir,
            &compute_cache_key("reader", "acme/api"),
            &CacheEntry::Derived(DerivedCacheEntry {
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
                    CacheEntry::Root(entry) => entry.generation_fingerprint(),
                    CacheEntry::Derived(_) | CacheEntry::Run(_) => panic!("expected root"),
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
        assert_eq!(first.access_token.as_ref(), "fresh-1");
        assert_eq!(second.access_token.as_ref(), "fresh-2");
        assert_ne!(first.cache_key, second.cache_key);
        assert_eq!(client.0.get(), 2);
    }

    #[test]
    fn run_rejects_root_profiles_before_minting() {
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
        assert!(matches!(result, Err(TokenError::RunRequiresDerived(_))));
        assert_eq!(client.0.get(), 0);
    }
}
