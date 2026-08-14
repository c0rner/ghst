use super::{
    AcquireRequest, AcquiredToken, TokenError, load_valid_root_entry, revoke_with_context,
    root_cache_key,
};
use crate::cache::{
    CACHE_SCHEMA_VERSION, CacheEntry, DerivedCacheEntry, SaveCacheEntry, cache_epoch,
    compute_cache_key, format_rfc3339, load_cache_entry, policy_fingerprint, save_cache_candidate,
};
use crate::config::{ProfileConfig, RootProfile};
use crate::repository::RepositoryError;
use crate::token::ScopedTokenClient;
use std::path::Path;
use time::OffsetDateTime;

pub fn acquire<C: ScopedTokenClient>(
    client: &C,
    request: &AcquireRequest<'_>,
    resolve_auto: impl FnMut() -> Result<String, RepositoryError>,
) -> Result<AcquiredToken, TokenError> {
    match request.config.profiles.get(request.profile_name) {
        Some(ProfileConfig::Root(profile)) => acquire_root(request, profile),
        Some(ProfileConfig::Derived(_)) => acquire_derived(client, request, resolve_auto),
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
    resolve_auto: impl FnMut() -> Result<String, RepositoryError>,
) -> Result<AcquiredToken, TokenError> {
    let prepared = super::scoped::prepare(
        request.config,
        request.cache_dir,
        request.profile_name,
        request.repositories,
        resolve_auto,
    )?;
    let policy = policy_fingerprint(
        &prepared.source.github_app.account,
        &prepared.scope,
        &prepared.permissions,
    );
    let generation = prepared.root.generation_fingerprint();
    let cache_key = compute_cache_key(request.profile_name, &prepared.scope);
    let provenance = DerivedProvenance {
        profile_name: request.profile_name,
        source_name: &prepared.profile.source,
        canonical_scope: &prepared.scope,
        policy: &policy,
        parent_generation: &generation,
        source_app: &prepared.source.github_app,
    };
    if let Some(entry) =
        load_valid_derived_entry(request.cache_dir, &cache_key, &provenance, request.now)?
    {
        return Ok(acquired_derived(entry));
    }
    mint_and_persist(
        client,
        request,
        MintRequest {
            cache_key: &cache_key,
            policy: &policy,
            prepared,
        },
    )
}

struct DerivedProvenance<'a> {
    profile_name: &'a str,
    source_name: &'a str,
    canonical_scope: &'a str,
    policy: &'a str,
    parent_generation: &'a str,
    source_app: &'a crate::config::GitHubAppConfig,
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
            && super::provenance::matches(
                provenance.source_app,
                &entry.source_authority_fingerprint,
            )
            && entry.repo_scope == provenance.canonical_scope
            && entry.policy_fingerprint == provenance.policy
            && entry.parent_generation == provenance.parent_generation
            && entry.expires_at.is_usable_at(now))
        .then_some(entry)),
        other @ (CacheEntry::Root(_) | CacheEntry::Run(_)) => {
            Err(TokenError::UnexpectedCacheKind {
                profile: provenance.profile_name.to_owned(),
                expected: "derived",
                actual: other.kind_name(),
            })
        }
    }
}

struct MintRequest<'a> {
    cache_key: &'a str,
    policy: &'a str,
    prepared: super::scoped::PreparedScopedToken<'a>,
}

fn mint_and_persist<C: ScopedTokenClient>(
    client: &C,
    request: &AcquireRequest<'_>,
    mint: MintRequest<'_>,
) -> Result<AcquiredToken, TokenError> {
    let epoch = cache_epoch(request.cache_dir)?;
    let generation = mint.prepared.root.generation_fingerprint();
    let secret = mint
        .prepared
        .source
        .github_app
        .client_secret
        .as_deref()
        .ok_or_else(|| TokenError::ClientSecretRequired(mint.prepared.profile.source.clone()))?;
    let received = request.now;
    let issued = super::scoped::issue(client, &mint.prepared, received)?;
    let candidate = CacheEntry::Derived(DerivedCacheEntry {
        version: CACHE_SCHEMA_VERSION,
        profile: request.profile_name.to_owned(),
        source_profile: mint.prepared.profile.source.clone(),
        source_authority_fingerprint: crate::cache::authority_fingerprint(
            &mint.prepared.source.github_app.client_id,
            &mint.prepared.source.github_app.account,
        ),
        parent_generation: mint.prepared.root.generation_fingerprint(),
        policy_fingerprint: mint.policy.to_owned(),
        github_user: mint.prepared.root.github_user,
        repo_scope: mint.prepared.scope.clone(),
        issued_at: format_rfc3339(received),
        expires_at: issued.expires_at,
        access_token: issued.access_token,
    });
    let root_key = root_cache_key(&mint.prepared.profile.source);
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
                mint.prepared.source,
                candidate.access_token(),
                TokenError::RootGenerationChanged(mint.prepared.profile.source.clone()),
            ));
        }
        Err(error) => {
            return Err(revoke_with_context(
                client,
                mint.prepared.source,
                candidate.access_token(),
                TokenError::Cache(error),
            ));
        }
    };
    match saved {
        SaveCacheEntry::Saved => match candidate {
            CacheEntry::Derived(entry) => Ok(acquired_derived(entry)),
            CacheEntry::Root(_) | CacheEntry::Run(_) => unreachable!("candidate is derived"),
        },
        SaveCacheEntry::Retained(retained) => {
            if let Err(source) = client.delete_token(
                &mint.prepared.source.github_app.client_id,
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
                other @ (CacheEntry::Root(_) | CacheEntry::Run(_)) => {
                    Err(TokenError::UnexpectedCacheKind {
                        profile: other.profile().to_owned(),
                        expected: "derived",
                        actual: other.kind_name(),
                    })
                }
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
