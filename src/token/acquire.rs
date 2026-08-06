use super::{
    AcquireRequest, AcquiredToken, TokenError, load_current_root_entry, load_valid_root_entry,
    revoke_with_context, root_cache_key, validate_scoped_expiry,
};
use crate::cache::{
    CACHE_SCHEMA_VERSION, CacheEntry, DerivedCacheEntry, RootCacheEntry, SaveCacheEntry,
    cache_epoch, compute_cache_key, format_rfc3339, load_cache_entry, policy_fingerprint,
    save_cache_candidate,
};
use crate::config::{Config, ProfileConfig, RootProfile};
use crate::github::{ScopedTokenClient, ScopedTokenResponse};
use crate::repository::RepositorySelection;
use std::collections::BTreeMap;
use std::path::Path;
use time::OffsetDateTime;

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
    let received = request.now;
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
