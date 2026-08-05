pub mod clear;

use crate::cache::{
    CACHE_SCHEMA_VERSION, CacheEntry, DerivedCacheEntry, RootCacheEntry, SaveCacheEntry,
    TokenExpiry, authority_fingerprint, cache_epoch, compute_cache_key, format_rfc3339,
    load_cache_entry, policy_fingerprint, save_cache_candidate,
};
use crate::config::{Config, GitHubAppConfig, ProfileConfig, RootProfile};
use crate::github::{
    AccessTokenResponse, GitHubError, RevokeTokenClient, RootTokenClient, ScopedTokenClient,
    ScopedTokenResponse,
};
use crate::repository::{RepositoryError, RepositorySelection};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use time::{Duration, OffsetDateTime};

const MAX_ROOT_LIFETIME_SECONDS: u64 = 8 * 60 * 60;
const MAX_SCOPED_LIFETIME: Duration = Duration::hours(8);
const SCOPED_EXPIRY_ROUNDING_TOLERANCE: Duration = Duration::seconds(1);

#[derive(Debug)]
pub enum TokenError {
    Cache(crate::cache::CacheError),
    GitHub(GitHubError),
    Repository(RepositoryError),
    ProfileNotFound(String),
    SourceProfileNotRoot {
        profile: String,
        source: String,
    },
    ClientSecretRequired(String),
    NoRootTokenCached(String),
    NoSourceTokenCached(String),
    RootScopeRejected(String),
    UnexpectedCacheKind {
        profile: String,
        expected: &'static str,
        actual: &'static str,
    },
    InconsistentCacheMetadata {
        profile: String,
        found: String,
    },
    StaleProvenance {
        profile: String,
        reason: &'static str,
    },
    RootGenerationChanged(String),
    InvalidLifetime {
        token_kind: &'static str,
        reason: String,
    },
    RevocationFailed {
        context: Box<Self>,
        source: GitHubError,
    },
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cache(error) => write!(f, "cache error: {error}"),
            Self::GitHub(error) => write!(f, "github error: {error}"),
            Self::Repository(error) => write!(f, "{error}"),
            Self::ProfileNotFound(profile) => {
                write!(f, "profile '{profile}' is not defined in configuration")
            }
            Self::SourceProfileNotRoot { profile, source } => write!(
                f,
                "derived profile '{profile}' references non-root source profile '{source}'"
            ),
            Self::ClientSecretRequired(profile) => write!(
                f,
                "root profile '{profile}' has no client secret; derived token minting is unavailable"
            ),
            Self::NoRootTokenCached(profile) => {
                write!(f, "no valid token cached for root profile '{profile}'")
            }
            Self::NoSourceTokenCached(profile) => {
                write!(
                    f,
                    "no valid token cached for root source profile '{profile}'"
                )
            }
            Self::RootScopeRejected(profile) => {
                write!(f, "root profile '{profile}' cannot be repository-scoped")
            }
            Self::UnexpectedCacheKind {
                profile,
                expected,
                actual,
            } => write!(
                f,
                "cache entry for profile '{profile}' has kind '{actual}', expected '{expected}'"
            ),
            Self::InconsistentCacheMetadata { profile, found } => write!(
                f,
                "cache entry for profile '{profile}' contains inconsistent profile metadata '{found}'"
            ),
            Self::StaleProvenance { profile, reason } => write!(
                f,
                "cached token for profile '{profile}' has stale provenance: {reason}"
            ),
            Self::RootGenerationChanged(profile) => write!(
                f,
                "root token for profile '{profile}' changed while minting; retry the token request"
            ),
            Self::InvalidLifetime { token_kind, reason } => {
                write!(f, "invalid {token_kind} token lifetime: {reason}")
            }
            Self::RevocationFailed { context, source } => write!(
                f,
                "{context}; additionally failed to revoke the unused token: {source}"
            ),
        }
    }
}

impl std::error::Error for TokenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cache(error) => Some(error),
            Self::GitHub(error) => Some(error),
            Self::Repository(error) => Some(error),
            Self::RevocationFailed { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<crate::cache::CacheError> for TokenError {
    fn from(error: crate::cache::CacheError) -> Self {
        Self::Cache(error)
    }
}

impl From<GitHubError> for TokenError {
    fn from(error: GitHubError) -> Self {
        Self::GitHub(error)
    }
}

impl From<RepositoryError> for TokenError {
    fn from(error: RepositoryError) -> Self {
        Self::Repository(error)
    }
}

#[cfg(test)]
mod error_tests {
    use super::TokenError;

    #[test]
    fn domain_errors_do_not_name_cli_commands_or_options() {
        for error in [
            TokenError::NoRootTokenCached("developer".into()),
            TokenError::NoSourceTokenCached("developer".into()),
            TokenError::RootScopeRejected("developer".into()),
        ] {
            let message = error.to_string();
            assert!(!message.contains("ghst"));
            assert!(!message.contains("--repo"));
        }
    }
}

pub struct AcquiredToken {
    pub access_token: crate::cache::AccessToken,
    pub expires_at: TokenExpiry,
    pub profile: String,
    pub repo_scope: String,
}

impl fmt::Debug for AcquiredToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcquiredToken")
            .field("access_token", &self.access_token)
            .field("expires_at", &self.expires_at)
            .field("profile", &self.profile)
            .field("repo_scope", &self.repo_scope)
            .finish()
    }
}

pub enum RootPersistence {
    Saved(RootCacheEntry),
    Retained(RootCacheEntry),
}

pub struct AcquireRequest<'a> {
    pub config: &'a Config,
    pub cache_dir: &'a Path,
    pub profile_name: &'a str,
    pub repositories: &'a [String],
    pub now: OffsetDateTime,
}

pub fn root_cache_key(profile_name: &str) -> String {
    compute_cache_key(profile_name, "all")
}

pub fn load_valid_root_entry(
    cache_dir: &Path,
    profile_name: &str,
    profile: &RootProfile,
    now: OffsetDateTime,
) -> Result<Option<RootCacheEntry>, TokenError> {
    Ok(
        load_current_root_entry(cache_dir, profile_name, &profile.github_app)?
            .filter(|entry| entry.expires_at.is_usable_at(now)),
    )
}

pub fn load_current_root_entry(
    cache_dir: &Path,
    profile_name: &str,
    github_app: &GitHubAppConfig,
) -> Result<Option<RootCacheEntry>, TokenError> {
    let key = root_cache_key(profile_name);
    let Some(entry) = load_cache_entry(cache_dir, &key)? else {
        return Ok(None);
    };
    if entry.profile() != profile_name {
        return Err(TokenError::InconsistentCacheMetadata {
            profile: profile_name.to_owned(),
            found: entry.profile().to_owned(),
        });
    }
    match entry {
        CacheEntry::Root(entry) => {
            let expected = authority_fingerprint(&github_app.client_id, &github_app.account);
            Ok(
                (entry.version == CACHE_SCHEMA_VERSION && entry.authority_fingerprint == expected)
                    .then_some(entry),
            )
        }
        CacheEntry::Derived(_) => Err(TokenError::UnexpectedCacheKind {
            profile: profile_name.to_owned(),
            expected: "root",
            actual: "derived",
        }),
    }
}

pub fn persist_root_response<C: RootTokenClient>(
    client: &C,
    profile: &RootProfile,
    profile_name: &str,
    cache_dir: &Path,
    response: AccessTokenResponse,
    now: OffsetDateTime,
    epoch: u64,
) -> Result<RootPersistence, TokenError> {
    let AccessTokenResponse {
        access_token,
        expires_in,
        refresh_token,
        ..
    } = response;
    drop(refresh_token);
    let expiry = match validate_root_expiry(expires_in, now) {
        Ok(expiry) => expiry,
        Err(error) => return Err(revoke_with_context(client, profile, &access_token, error)),
    };
    let user = match client.get_user(access_token.as_ref()) {
        Ok(user) => user,
        Err(error) => {
            return Err(revoke_with_context(
                client,
                profile,
                &access_token,
                TokenError::GitHub(error),
            ));
        }
    };
    let candidate = CacheEntry::Root(RootCacheEntry {
        version: CACHE_SCHEMA_VERSION,
        profile: profile_name.to_owned(),
        authority_fingerprint: authority_fingerprint(
            &profile.github_app.client_id,
            &profile.github_app.account,
        ),
        github_user: user.login,
        issued_at: format_rfc3339(now),
        expires_at: expiry,
        access_token,
    });
    let result = match save_cache_candidate(
        cache_dir,
        &root_cache_key(profile_name),
        &candidate,
        epoch,
        None,
    ) {
        Ok(result) => result,
        Err(error) => {
            return Err(revoke_with_context(
                client,
                profile,
                candidate.access_token(),
                TokenError::Cache(error),
            ));
        }
    };
    match result {
        SaveCacheEntry::Saved => match candidate {
            CacheEntry::Root(entry) => Ok(RootPersistence::Saved(entry)),
            CacheEntry::Derived(_) => unreachable!("candidate is root"),
        },
        SaveCacheEntry::Retained(entry) => match *entry {
            CacheEntry::Root(entry) => {
                let cleanup = revoke_with_context(
                    client,
                    profile,
                    candidate.access_token(),
                    TokenError::StaleProvenance {
                        profile: profile_name.to_owned(),
                        reason: "a compatible concurrent root cache winner was retained",
                    },
                );
                if matches!(cleanup, TokenError::RevocationFailed { .. }) {
                    Err(cleanup)
                } else {
                    Ok(RootPersistence::Retained(entry))
                }
            }
            entry @ CacheEntry::Derived(_) => Err(TokenError::UnexpectedCacheKind {
                profile: profile_name.to_owned(),
                expected: "root",
                actual: entry.kind_name(),
            }),
        },
    }
}

pub fn acquire<C: ScopedTokenClient>(
    client: &C,
    request: &AcquireRequest<'_>,
    resolve_auto: impl FnMut() -> Result<String, crate::git::GitError>,
) -> Result<AcquiredToken, TokenError> {
    match request.config.profiles.get(request.profile_name) {
        Some(ProfileConfig::Root(profile)) => acquire_root(request, profile),
        Some(ProfileConfig::Derived(profile)) => {
            acquire_derived(client, request, profile, resolve_auto)
        }
        None => Err(TokenError::ProfileNotFound(request.profile_name.to_owned())),
    }
}

fn acquire_root(
    request: &AcquireRequest<'_>,
    profile: &RootProfile,
) -> Result<AcquiredToken, TokenError> {
    if !request.repositories.is_empty() {
        return Err(TokenError::RootScopeRejected(
            request.profile_name.to_owned(),
        ));
    }
    let entry = load_valid_root_entry(
        request.cache_dir,
        request.profile_name,
        profile,
        request.now,
    )?
    .ok_or_else(|| TokenError::NoRootTokenCached(request.profile_name.to_owned()))?;
    Ok(AcquiredToken {
        access_token: entry.access_token,
        expires_at: entry.expires_at,
        profile: request.profile_name.to_owned(),
        repo_scope: "all".to_owned(),
    })
}

fn acquire_derived<C: ScopedTokenClient>(
    client: &C,
    request: &AcquireRequest<'_>,
    profile: &crate::config::DerivedProfile,
    resolve_auto: impl FnMut() -> Result<String, crate::git::GitError>,
) -> Result<AcquiredToken, TokenError> {
    let selection =
        RepositorySelection::resolve(request.repositories, &profile.repo, resolve_auto)?;
    let scope = selection.canonical();
    let source = resolve_source_profile(request.config, request.profile_name, &profile.source)?;
    let repositories = selection.repository_names(&source.github_app.account)?;
    let permissions = permission_request(&profile.permissions);
    let policy = policy_fingerprint(&source.github_app.account, &scope, &permissions);
    let root = load_current_root_entry(request.cache_dir, &profile.source, &source.github_app)?
        .ok_or_else(|| TokenError::NoSourceTokenCached(profile.source.clone()))?;
    let generation = root.generation_fingerprint();
    let cache_key = compute_cache_key(request.profile_name, &scope);
    let provenance = DerivedProvenance {
        profile_name: request.profile_name,
        source_name: &profile.source,
        canonical_scope: &scope,
        policy: &policy,
        parent_generation: &generation,
    };
    if let Some(entry) =
        load_valid_derived_entry(request.cache_dir, &cache_key, &provenance, request.now)?
    {
        return Ok(acquired_derived(entry));
    }
    if !root.expires_at.is_usable_at(request.now) {
        return Err(TokenError::NoSourceTokenCached(profile.source.clone()));
    }
    mint_and_persist(
        client,
        request,
        MintRequest {
            cache_key: &cache_key,
            source_name: &profile.source,
            source_profile: source,
            canonical_scope: &scope,
            repositories: repositories.as_deref(),
            permissions: &permissions,
            policy: &policy,
            root_entry: root,
        },
    )
}

fn resolve_source_profile<'a>(
    config: &'a Config,
    profile_name: &str,
    source_name: &str,
) -> Result<&'a RootProfile, TokenError> {
    match config.profiles.get(source_name) {
        Some(ProfileConfig::Root(root)) => Ok(root),
        Some(ProfileConfig::Derived(_)) => Err(TokenError::SourceProfileNotRoot {
            profile: profile_name.to_owned(),
            source: source_name.to_owned(),
        }),
        None => Err(TokenError::ProfileNotFound(source_name.to_owned())),
    }
}

fn permission_request(
    permissions: &BTreeMap<String, crate::config::PermissionLevel>,
) -> BTreeMap<String, String> {
    permissions
        .iter()
        .map(|(name, level)| (name.clone(), level.to_string()))
        .collect()
}

struct DerivedProvenance<'a> {
    profile_name: &'a str,
    source_name: &'a str,
    canonical_scope: &'a str,
    policy: &'a str,
    parent_generation: &'a str,
}

fn load_valid_derived_entry(
    cache_dir: &Path,
    cache_key: &str,
    provenance: &DerivedProvenance<'_>,
    now: OffsetDateTime,
) -> Result<Option<DerivedCacheEntry>, TokenError> {
    let Some(entry) = load_cache_entry(cache_dir, cache_key)? else {
        return Ok(None);
    };
    if entry.profile() != provenance.profile_name {
        return Err(TokenError::InconsistentCacheMetadata {
            profile: provenance.profile_name.to_owned(),
            found: entry.profile().to_owned(),
        });
    }
    match entry {
        CacheEntry::Derived(entry) => Ok((entry.version == CACHE_SCHEMA_VERSION
            && entry.source_profile == provenance.source_name
            && entry.repo_scope == provenance.canonical_scope
            && entry.policy_fingerprint == provenance.policy
            && entry.parent_generation == provenance.parent_generation
            && entry.expires_at.is_usable_at(now))
        .then_some(entry)),
        CacheEntry::Root(_) => Err(TokenError::UnexpectedCacheKind {
            profile: provenance.profile_name.to_owned(),
            expected: "derived",
            actual: "root",
        }),
    }
}

struct MintRequest<'a> {
    cache_key: &'a str,
    source_name: &'a str,
    source_profile: &'a RootProfile,
    canonical_scope: &'a str,
    repositories: Option<&'a [String]>,
    permissions: &'a BTreeMap<String, String>,
    policy: &'a str,
    root_entry: RootCacheEntry,
}

fn mint_and_persist<C: ScopedTokenClient>(
    client: &C,
    request: &AcquireRequest<'_>,
    mint: MintRequest<'_>,
) -> Result<AcquiredToken, TokenError> {
    let epoch = cache_epoch(request.cache_dir)?;
    let generation = mint.root_entry.generation_fingerprint();
    let secret = mint
        .source_profile
        .github_app
        .client_secret
        .as_deref()
        .ok_or_else(|| TokenError::ClientSecretRequired(mint.source_name.to_owned()))?;
    let ScopedTokenResponse {
        token, expires_at, ..
    } = client.create_scoped_token(
        &mint.source_profile.github_app.client_id,
        secret,
        mint.root_entry.access_token.as_ref(),
        &mint.source_profile.github_app.account,
        mint.repositories,
        mint.permissions,
    )?;
    let received = OffsetDateTime::now_utc();
    let expiry = match validate_scoped_expiry(expires_at.as_deref(), received) {
        Ok(expiry) => expiry,
        Err(error) => {
            return Err(revoke_with_context(
                client,
                mint.source_profile,
                &token,
                error,
            ));
        }
    };
    let candidate = CacheEntry::Derived(DerivedCacheEntry {
        version: CACHE_SCHEMA_VERSION,
        profile: request.profile_name.to_owned(),
        source_profile: mint.source_name.to_owned(),
        parent_generation: mint.root_entry.generation_fingerprint(),
        policy_fingerprint: mint.policy.to_owned(),
        github_user: mint.root_entry.github_user,
        repo_scope: mint.canonical_scope.to_owned(),
        issued_at: format_rfc3339(received),
        expires_at: expiry,
        access_token: token,
    });
    let root_key = root_cache_key(mint.source_name);
    let saved = match save_cache_candidate(
        request.cache_dir,
        mint.cache_key,
        &candidate,
        epoch,
        Some((&root_key, &generation)),
    ) {
        Ok(result) => result,
        Err(crate::cache::CacheError::RootGenerationChanged) => {
            return Err(revoke_with_context(
                client,
                mint.source_profile,
                candidate.access_token(),
                TokenError::RootGenerationChanged(mint.source_name.to_owned()),
            ));
        }
        Err(error) => {
            return Err(revoke_with_context(
                client,
                mint.source_profile,
                candidate.access_token(),
                TokenError::Cache(error),
            ));
        }
    };
    match saved {
        SaveCacheEntry::Saved => match candidate {
            CacheEntry::Derived(entry) => Ok(acquired_derived(entry)),
            CacheEntry::Root(_) => unreachable!("candidate is derived"),
        },
        SaveCacheEntry::Retained(retained) => {
            if let Err(source) = client.delete_token(
                &mint.source_profile.github_app.client_id,
                secret,
                candidate.access_token().as_ref(),
            ) {
                return Err(TokenError::RevocationFailed {
                    context: Box::new(TokenError::StaleProvenance {
                        profile: request.profile_name.to_owned(),
                        reason: "a compatible concurrent cache winner retained the token",
                    }),
                    source,
                });
            }
            match *retained {
                CacheEntry::Derived(entry) => Ok(acquired_derived(entry)),
                CacheEntry::Root(entry) => Err(TokenError::UnexpectedCacheKind {
                    profile: entry.profile,
                    expected: "derived",
                    actual: "root",
                }),
            }
        }
    }
}

fn acquired_derived(entry: DerivedCacheEntry) -> AcquiredToken {
    AcquiredToken {
        access_token: entry.access_token,
        expires_at: entry.expires_at,
        profile: entry.profile,
        repo_scope: entry.repo_scope,
    }
}

pub fn validate_root_expiry(
    expires_in: Option<u64>,
    now: OffsetDateTime,
) -> Result<TokenExpiry, TokenError> {
    let seconds = expires_in.ok_or_else(|| TokenError::InvalidLifetime {
        token_kind: "root",
        reason: "response did not contain expires_in".into(),
    })?;
    if seconds == 0 || seconds > MAX_ROOT_LIFETIME_SECONDS {
        let reason = if seconds == 0 {
            "expires_in must be positive".into()
        } else {
            format!("expires_in of {seconds} seconds exceeds the supported eight-hour maximum")
        };
        return Err(TokenError::InvalidLifetime {
            token_kind: "root",
            reason,
        });
    }
    let seconds = i64::try_from(seconds).map_err(|_| TokenError::InvalidLifetime {
        token_kind: "root",
        reason: "expires_in cannot be represented safely".into(),
    })?;
    let expiry = TokenExpiry::new(now + Duration::seconds(seconds));
    if !expiry.is_usable_at(now) {
        return Err(TokenError::InvalidLifetime {
            token_kind: "root",
            reason: "expires_in is not beyond the 30-second safety margin".into(),
        });
    }
    Ok(expiry)
}

pub fn validate_scoped_expiry(
    value: Option<&str>,
    now: OffsetDateTime,
) -> Result<TokenExpiry, TokenError> {
    let value = value.ok_or_else(|| TokenError::InvalidLifetime {
        token_kind: "scoped",
        reason: "response did not contain expires_at".into(),
    })?;
    let expiry = TokenExpiry::parse(value).map_err(|_| TokenError::InvalidLifetime {
        token_kind: "scoped",
        reason: "expires_at is not valid RFC 3339".into(),
    })?;
    if !expiry.is_usable_at(now) {
        return Err(TokenError::InvalidLifetime {
            token_kind: "scoped",
            reason: "expires_at is not beyond the 30-second safety margin".into(),
        });
    }
    if expiry.value() > now + MAX_SCOPED_LIFETIME + SCOPED_EXPIRY_ROUNDING_TOLERANCE {
        return Err(TokenError::InvalidLifetime {
            token_kind: "scoped",
            reason: "expires_at exceeds the supported eight-hour maximum and one-second timestamp rounding tolerance".into(),
        });
    }
    Ok(expiry)
}

fn revoke_with_context<C: RevokeTokenClient + ?Sized>(
    client: &C,
    profile: &RootProfile,
    token: &crate::cache::AccessToken,
    context: TokenError,
) -> TokenError {
    let Some(secret) = profile.github_app.client_secret.as_deref() else {
        tracing::warn!(
            "client secret unavailable; unused remote token could not be revoked and may remain active until GitHub invalidates it or it is manually revoked"
        );
        return context;
    };
    match client.delete_token(&profile.github_app.client_id, secret, token.as_ref()) {
        Ok(()) => context,
        Err(source) => TokenError::RevocationFailed {
            context: Box::new(context),
            source,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{delete_cache_entry, save_cache_entry};
    use crate::github::{RevokeTokenClient, UserResponse};
    use std::cell::RefCell;

    const CONFIG: &str = r#"
version = 1
default_profile = "reader"

[profile.developer]
github_app.account = "acme"
github_app.client_id = "id"
github_app.client_secret = "secret"

[profile.reader]
source = "developer"
repo = "acme/api"
permissions = { contents = "read", pull_requests = "write" }
"#;

    struct MockClient {
        scoped: RefCell<Option<Result<ScopedTokenResponse, GitHubError>>>,
        request: RefCell<Option<serde_json::Value>>,
        revoked: RefCell<Vec<String>>,
        revoke_fails: bool,
    }

    impl RevokeTokenClient for MockClient {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            access_token: &str,
        ) -> Result<(), GitHubError> {
            self.revoked.borrow_mut().push(access_token.to_owned());
            if self.revoke_fails {
                Err(GitHubError::Http {
                    status: 500,
                    message: "revocation failed".into(),
                })
            } else {
                Ok(())
            }
        }
    }

    impl RootTokenClient for MockClient {
        fn get_user(&self, _access_token: &str) -> Result<UserResponse, GitHubError> {
            Ok(UserResponse {
                login: "octocat".into(),
                id: 1,
                name: None,
                email: None,
            })
        }
    }

    impl ScopedTokenClient for MockClient {
        fn create_scoped_token(
            &self,
            client_id: &str,
            client_secret: &str,
            root_token: &str,
            target: &str,
            repositories: Option<&[String]>,
            permissions: &BTreeMap<String, String>,
        ) -> Result<ScopedTokenResponse, GitHubError> {
            self.request.replace(Some(serde_json::json!({
                "client_id": client_id,
                "client_secret": client_secret,
                "root_token": root_token,
                "target": target,
                "repositories": repositories,
                "permissions": permissions,
            })));
            self.scoped.borrow_mut().take().unwrap()
        }
    }

    fn client(response: ScopedTokenResponse) -> MockClient {
        MockClient {
            scoped: RefCell::new(Some(Ok(response))),
            request: RefCell::new(None),
            revoked: RefCell::new(Vec::new()),
            revoke_fails: false,
        }
    }

    fn cache_root(cache_dir: &Path, now: OffsetDateTime, token: &str) {
        let entry = CacheEntry::Root(RootCacheEntry {
            version: CACHE_SCHEMA_VERSION,
            profile: "developer".into(),
            authority_fingerprint: authority_fingerprint("id", "acme"),
            github_user: "octocat".into(),
            issued_at: format_rfc3339(now),
            expires_at: TokenExpiry::new(now + Duration::hours(2)),
            access_token: token.into(),
        });
        save_cache_entry(cache_dir, &root_cache_key("developer"), &entry).unwrap();
    }

    #[test]
    fn root_lifetime_requires_positive_bounded_value_and_margin() {
        let now = OffsetDateTime::now_utc();
        for value in [None, Some(0), Some(30), Some(MAX_ROOT_LIFETIME_SECONDS + 1)] {
            assert!(matches!(
                validate_root_expiry(value, now),
                Err(TokenError::InvalidLifetime { .. })
            ));
        }
        assert_eq!(
            validate_root_expiry(Some(MAX_ROOT_LIFETIME_SECONDS), now)
                .unwrap()
                .value(),
            now + Duration::hours(8)
        );
    }

    #[test]
    fn scoped_lifetime_enforces_margin_maximum_and_rounding_tolerance() {
        let now = OffsetDateTime::now_utc();
        for value in [
            Some("not-a-timestamp".to_owned()),
            Some(TokenExpiry::new(now + Duration::seconds(30)).to_string()),
            Some(TokenExpiry::new(now + Duration::hours(8) + Duration::seconds(2)).to_string()),
        ] {
            assert!(matches!(
                validate_scoped_expiry(value.as_deref(), now),
                Err(TokenError::InvalidLifetime { .. })
            ));
        }
        let issued = OffsetDateTime::parse(
            "2026-08-01T17:20:25.889841154Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        assert!(validate_scoped_expiry(Some("2026-08-02T01:20:26.000Z"), issued).is_ok());
    }

    #[test]
    fn root_authority_and_kind_are_validated() {
        let now = OffsetDateTime::now_utc();
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_root(&cache_dir, now, "root");
        let config: Config = CONFIG.parse().unwrap();
        let ProfileConfig::Root(root) = config.profiles.get("developer").unwrap() else {
            panic!("expected root");
        };
        assert!(
            load_current_root_entry(&cache_dir, "developer", &root.github_app)
                .unwrap()
                .is_some()
        );
        let mismatched = GitHubAppConfig {
            account: "other".into(),
            client_id: "id".into(),
            client_secret: None,
        };
        assert!(
            load_current_root_entry(&cache_dir, "developer", &mismatched)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn root_acquisition_returns_cached_token_and_rejects_repository_scope() {
        let now = OffsetDateTime::now_utc();
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_root(&cache_dir, now, "root-token");
        let config: Config = CONFIG.parse().unwrap();
        let client = client(ScopedTokenResponse {
            token: "unused".into(),
            expires_at: None,
            permissions: None,
            repositories: None,
        });
        let acquired = acquire(
            &client,
            &AcquireRequest {
                config: &config,
                cache_dir: &cache_dir,
                profile_name: "developer",
                repositories: &[],
                now,
            },
            || panic!("auto not expected"),
        )
        .unwrap();
        assert_eq!(acquired.access_token.as_ref(), "root-token");
        assert_eq!(acquired.repo_scope, "all");

        assert!(matches!(
            acquire(
                &client,
                &AcquireRequest {
                    config: &config,
                    cache_dir: &cache_dir,
                    profile_name: "developer",
                    repositories: &["acme/api".into()],
                    now,
                },
                || panic!("auto not expected"),
            ),
            Err(TokenError::RootScopeRejected(profile)) if profile == "developer"
        ));
    }

    #[test]
    fn invalid_root_response_is_revoked_and_not_persisted() {
        let config: Config = CONFIG.parse().unwrap();
        let ProfileConfig::Root(root) = config.profiles.get("developer").unwrap() else {
            panic!("expected root");
        };
        let client = client(ScopedTokenResponse {
            token: "unused".into(),
            expires_at: None,
            permissions: None,
            repositories: None,
        });
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let response = AccessTokenResponse {
            access_token: "bad-root".into(),
            token_type: "bearer".into(),
            expires_in: None,
            refresh_token: Some(zeroize::Zeroizing::new("refresh".into())),
            refresh_token_expires_in: Some(3600),
            scope: None,
        };
        assert!(matches!(
            persist_root_response(
                &client,
                root,
                "developer",
                &cache_dir,
                response,
                OffsetDateTime::now_utc(),
                cache_epoch(&cache_dir).unwrap(),
            ),
            Err(TokenError::InvalidLifetime { .. })
        ));
        assert_eq!(&*client.revoked.borrow(), &["bad-root"]);
        assert!(
            load_cache_entry(&cache_dir, &root_cache_key("developer"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn derived_acquisition_sends_exact_narrowing_request() {
        let now = OffsetDateTime::now_utc();
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_root(&cache_dir, now, "root-token");
        let expiry = TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(6)).to_string();
        let client = client(ScopedTokenResponse {
            token: "child-token".into(),
            expires_at: Some(expiry),
            permissions: None,
            repositories: None,
        });
        let config: Config = CONFIG.parse().unwrap();
        let acquired = acquire(
            &client,
            &AcquireRequest {
                config: &config,
                cache_dir: &cache_dir,
                profile_name: "reader",
                repositories: &[],
                now,
            },
            || panic!("auto not expected"),
        )
        .unwrap();
        assert_eq!(acquired.access_token.as_ref(), "child-token");
        assert_eq!(acquired.repo_scope, "acme/api");
        assert_eq!(
            client.request.borrow().as_ref().unwrap(),
            &serde_json::json!({
                "client_id": "id",
                "client_secret": "secret",
                "root_token": "root-token",
                "target": "acme",
                "repositories": ["api"],
                "permissions": {"contents": "read", "pull_requests": "write"},
            })
        );
    }

    #[test]
    fn invalid_scoped_response_is_revoked_without_cache_entry() {
        let now = OffsetDateTime::now_utc();
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_root(&cache_dir, now, "root-token");
        let client = client(ScopedTokenResponse {
            token: "bad-child".into(),
            expires_at: None,
            permissions: None,
            repositories: None,
        });
        let config: Config = CONFIG.parse().unwrap();
        assert!(matches!(
            acquire(
                &client,
                &AcquireRequest {
                    config: &config,
                    cache_dir: &cache_dir,
                    profile_name: "reader",
                    repositories: &[],
                    now,
                },
                || panic!("auto not expected"),
            ),
            Err(TokenError::InvalidLifetime { .. })
        ));
        assert_eq!(&*client.revoked.borrow(), &["bad-child"]);
        assert!(
            load_cache_entry(&cache_dir, &compute_cache_key("reader", "acme/api"))
                .unwrap()
                .is_none()
        );
    }

    struct GenerationChangingClient<'a> {
        cache_dir: &'a Path,
        now: OffsetDateTime,
        revoked: RefCell<Vec<String>>,
    }

    impl RevokeTokenClient for GenerationChangingClient<'_> {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            access_token: &str,
        ) -> Result<(), GitHubError> {
            self.revoked.borrow_mut().push(access_token.to_owned());
            Ok(())
        }
    }

    impl ScopedTokenClient for GenerationChangingClient<'_> {
        fn create_scoped_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            _root_token: &str,
            _target: &str,
            _repositories: Option<&[String]>,
            _permissions: &BTreeMap<String, String>,
        ) -> Result<ScopedTokenResponse, GitHubError> {
            let key = root_cache_key("developer");
            delete_cache_entry(self.cache_dir, &key).unwrap();
            cache_root(self.cache_dir, self.now, "replacement-root");
            Ok(ScopedTokenResponse {
                token: "orphaned-child".into(),
                expires_at: Some(
                    TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(1)).to_string(),
                ),
                permissions: None,
                repositories: None,
            })
        }
    }

    #[test]
    fn root_generation_change_revokes_candidate_and_requests_retry() {
        let now = OffsetDateTime::now_utc();
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_root(&cache_dir, now, "root-token");
        let client = GenerationChangingClient {
            cache_dir: &cache_dir,
            now,
            revoked: RefCell::new(Vec::new()),
        };
        let config: Config = CONFIG.parse().unwrap();
        assert!(matches!(
            acquire(
                &client,
                &AcquireRequest {
                    config: &config,
                    cache_dir: &cache_dir,
                    profile_name: "reader",
                    repositories: &[],
                    now,
                },
                || panic!("auto not expected"),
            ),
            Err(TokenError::RootGenerationChanged(profile)) if profile == "developer"
        ));
        assert_eq!(&*client.revoked.borrow(), &["orphaned-child"]);
    }

    #[test]
    fn cached_derived_token_remains_usable_after_root_expiry() {
        let now = OffsetDateTime::now_utc();
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_root(&cache_dir, now, "root-token");
        let config: Config = CONFIG.parse().unwrap();
        let first_client = client(ScopedTokenResponse {
            token: "child-token".into(),
            expires_at: Some(
                TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(6)).to_string(),
            ),
            permissions: None,
            repositories: None,
        });
        let request = AcquireRequest {
            config: &config,
            cache_dir: &cache_dir,
            profile_name: "reader",
            repositories: &[],
            now,
        };
        acquire(&first_client, &request, || panic!("auto not expected")).unwrap();

        let root_key = root_cache_key("developer");
        let CacheEntry::Root(mut root) = load_cache_entry(&cache_dir, &root_key).unwrap().unwrap()
        else {
            panic!("expected root");
        };
        delete_cache_entry(&cache_dir, &root_key).unwrap();
        root.expires_at = TokenExpiry::new(now - Duration::minutes(1));
        save_cache_entry(&cache_dir, &root_key, &CacheEntry::Root(root)).unwrap();

        let unused_client = MockClient {
            scoped: RefCell::new(None),
            request: RefCell::new(None),
            revoked: RefCell::new(Vec::new()),
            revoke_fails: false,
        };
        let acquired = acquire(&unused_client, &request, || panic!("auto not expected")).unwrap();
        assert_eq!(acquired.access_token.as_ref(), "child-token");
        assert!(unused_client.request.borrow().is_none());
    }
}
