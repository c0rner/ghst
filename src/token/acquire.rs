use super::{
    AcquireRequest, AcquiredToken, TokenError, load_valid_root_entry, revoke_with_context,
    root_cache_key,
};
use crate::cache::{
    CACHE_SCHEMA_VERSION, CacheEntry, DerivedCacheEntry, ReplaceCacheEntry, SaveCacheEntry,
    cache_epoch, compute_cache_key, load_cache_entry, policy_fingerprint, replace_cache_candidate,
    save_cache_candidate,
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
    acquire_with_clock(client, request, resolve_auto, OffsetDateTime::now_utc)
}

pub(super) fn acquire_with_clock<
    C: ScopedTokenClient,
    R: FnMut() -> Result<String, RepositoryError>,
    N: FnMut() -> OffsetDateTime,
>(
    client: &C,
    request: &AcquireRequest<'_>,
    resolve_auto: R,
    mut now: N,
) -> Result<AcquiredToken, TokenError> {
    tracing::debug!(
        profile = request.profile_name,
        requested_repositories = ?request.repositories,
        "starting token acquisition"
    );
    match request.config.profiles.get(request.profile_name) {
        Some(ProfileConfig::Root(profile)) => {
            tracing::debug!(
                profile = request.profile_name,
                profile_kind = "root",
                "resolved token profile"
            );
            acquire_root(request, profile, now())
        }
        Some(ProfileConfig::Derived(_)) => {
            tracing::debug!(
                profile = request.profile_name,
                profile_kind = "derived",
                "resolved token profile"
            );
            acquire_derived(client, request, resolve_auto, &mut now)
        }
        None => Err(TokenError::ProfileNotFound(request.profile_name.to_owned())),
    }
}

fn acquire_root(
    request: &AcquireRequest<'_>,
    profile: &RootProfile,
    now: OffsetDateTime,
) -> Result<AcquiredToken, TokenError> {
    if !request.repositories.is_empty() {
        return Err(TokenError::RootScopeRejected(
            request.profile_name.to_owned(),
        ));
    }
    let entry = load_valid_root_entry(request.cache_dir, request.profile_name, profile, now)?
        .ok_or_else(|| TokenError::NoRootTokenCached(request.profile_name.to_owned()))?;
    tracing::debug!(profile = request.profile_name, expires_at = %entry.expires_at, "returning cached root token");
    Ok(AcquiredToken {
        access_token: entry.access_token,
        expires_at: entry.expires_at,
        profile: request.profile_name.to_owned(),
        repo_scope: "all".to_owned(),
    })
}

fn acquire_derived<
    C: ScopedTokenClient,
    R: FnMut() -> Result<String, RepositoryError>,
    N: FnMut() -> OffsetDateTime,
>(
    client: &C,
    request: &AcquireRequest<'_>,
    resolve_auto: R,
    now: &mut N,
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
    tracing::debug!(
        profile = request.profile_name,
        source_profile = prepared.profile.source,
        account = prepared.source.github_app.account,
        repo_scope = prepared.scope,
        permissions = ?prepared.permissions,
        cache_key,
        "prepared derived token acquisition"
    );
    let provenance = DerivedProvenance {
        profile_name: request.profile_name,
        source_name: &prepared.profile.source,
        canonical_scope: &prepared.scope,
        policy: &policy,
        parent_generation: &generation,
        source_app: &prepared.source.github_app,
    };
    let renewal = match classify_derived_entry(request.cache_dir, &cache_key, &provenance, now())? {
        CachedDerived::Fresh(entry) => {
            tracing::debug!(profile = request.profile_name, expires_at = %entry.expires_at, "returning fresh cached derived token");
            return Ok(acquired_derived(entry));
        }
        CachedDerived::Renewable(entry) => {
            tracing::debug!(profile = request.profile_name, expires_at = %entry.expires_at, "cached derived token is in the renewal window");
            Some(entry)
        }
        CachedDerived::MissingOrUnsafe => {
            tracing::debug!(
                profile = request.profile_name,
                "no reusable derived token is cached; a new token is required"
            );
            None
        }
    };
    mint_and_persist(
        client,
        request,
        MintRequest {
            cache_key: &cache_key,
            policy: &policy,
            prepared,
            renewal,
        },
        now,
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

enum CachedDerived {
    Fresh(DerivedCacheEntry),
    Renewable(DerivedCacheEntry),
    MissingOrUnsafe,
}

fn classify_derived_entry(
    cache_dir: &Path,
    cache_key: &str,
    provenance: &DerivedProvenance<'_>,
    now: OffsetDateTime,
) -> Result<CachedDerived, TokenError> {
    let Some(entry) = load_cache_entry(cache_dir, cache_key)? else {
        tracing::debug!(
            profile = provenance.profile_name,
            cache_key,
            "derived token cache miss"
        );
        return Ok(CachedDerived::MissingOrUnsafe);
    };
    if entry.profile() != provenance.profile_name {
        return Err(TokenError::InconsistentCacheMetadata {
            profile: provenance.profile_name.to_owned(),
            found: entry.profile().to_owned(),
        });
    }
    match entry {
        CacheEntry::Derived(entry) => {
            let rejection = if entry.version != CACHE_SCHEMA_VERSION {
                Some("schema version is not current")
            } else if entry.source_profile != provenance.source_name {
                Some("source profile changed")
            } else if !super::provenance::matches(
                provenance.source_app,
                &entry.source_authority_fingerprint,
            ) {
                Some("source GitHub App authority changed")
            } else if entry.repo_scope != provenance.canonical_scope {
                Some("repository scope changed")
            } else if entry.policy_fingerprint != provenance.policy {
                Some("permissions or target account changed")
            } else if entry.parent_generation != provenance.parent_generation {
                Some("parent root token generation changed")
            } else if !entry.expires_at.is_safe_to_handoff_at(now) {
                Some("token is expired or inside the handoff safety margin")
            } else {
                None
            };
            if let Some(reason) = rejection {
                tracing::debug!(
                    profile = provenance.profile_name,
                    cache_key,
                    expires_at = %entry.expires_at,
                    reason,
                    "cached derived token was rejected"
                );
                Ok(CachedDerived::MissingOrUnsafe)
            } else if entry.expires_at.is_due_for_renewal_at(now) {
                Ok(CachedDerived::Renewable(entry))
            } else {
                Ok(CachedDerived::Fresh(entry))
            }
        }
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
    renewal: Option<DerivedCacheEntry>,
}

fn mint_and_persist<C: ScopedTokenClient, N: FnMut() -> OffsetDateTime>(
    client: &C,
    request: &AcquireRequest<'_>,
    mint: MintRequest<'_>,
    now: &mut N,
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
    tracing::debug!(
        profile = request.profile_name,
        source_profile = mint.prepared.profile.source,
        repo_scope = mint.prepared.scope,
        renewal = mint.renewal.is_some(),
        "minting derived token"
    );
    let request_time = now();
    if !mint
        .prepared
        .root
        .expires_at
        .is_safe_to_handoff_at(request_time)
        && let Some(entry) = mint.renewal
    {
        tracing::debug!(
            profile = request.profile_name,
            root_expires_at = %mint.prepared.root.expires_at,
            derived_expires_at = %entry.expires_at,
            "root token cannot safely mint a replacement; returning provenance-valid cached derived token"
        );
        return Ok(acquired_derived(entry));
    }
    let issued = super::scoped::issue(client, &mint.prepared, request_time, now)?;
    tracing::debug!(profile = request.profile_name, expires_at = %issued.expires_at, "received valid derived token from GitHub");
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
        expires_at: issued.expires_at,
        access_token: issued.access_token,
    });
    let root_key = root_cache_key(&mint.prepared.profile.source);
    let persistence = persist_candidate(
        request.cache_dir,
        mint.cache_key,
        mint.renewal,
        &candidate,
        epoch,
        (&root_key, &generation),
        issued.received_at,
    );
    let saved = match persistence {
        Ok(result) => result,
        Err(crate::cache::CacheError::RootGenerationChanged) => {
            tracing::debug!(
                profile = request.profile_name,
                "root token generation changed while persisting derived token; revoking candidate"
            );
            return Err(revoke_with_context(
                client,
                mint.prepared.source,
                candidate.access_token(),
                TokenError::RootGenerationChanged(mint.prepared.profile.source.clone()),
            ));
        }
        Err(error) => {
            tracing::debug!(profile = request.profile_name, error = %error, "failed to persist derived token; revoking candidate");
            return Err(revoke_with_context(
                client,
                mint.prepared.source,
                candidate.access_token(),
                TokenError::Cache(error),
            ));
        }
    };
    finish_persisted_candidate(
        client,
        request,
        mint.prepared.source,
        secret,
        candidate,
        saved,
    )
}

fn finish_persisted_candidate<C: ScopedTokenClient>(
    client: &C,
    request: &AcquireRequest<'_>,
    source: &crate::config::RootProfile,
    secret: &str,
    candidate: CacheEntry,
    saved: PersistedCandidate,
) -> Result<AcquiredToken, TokenError> {
    match saved {
        PersistedCandidate::Saved(SaveCacheEntry::Saved) => {
            tracing::debug!(
                profile = request.profile_name,
                "persisted new derived token"
            );
            Ok(acquired_candidate(candidate))
        }
        PersistedCandidate::Saved(SaveCacheEntry::Retained(retained))
        | PersistedCandidate::Renewed(ReplaceCacheEntry::Retained(retained)) => {
            tracing::debug!(
                profile = request.profile_name,
                "compatible concurrent derived token won the cache race; revoking unused candidate"
            );
            revoke_candidate(
                client,
                request,
                &source.github_app.client_id,
                secret,
                &candidate,
            )?;
            acquired_retained(*retained)
        }
        PersistedCandidate::Renewed(ReplaceCacheEntry::Replaced(displaced)) => {
            tracing::debug!(
                profile = request.profile_name,
                "persisted renewed derived token; revoking displaced token"
            );
            if let Err(source) = client.delete_token(
                &source.github_app.client_id,
                secret,
                displaced.access_token().as_ref(),
            ) {
                return Err(TokenError::RevocationFailed {
                    context: Box::new(TokenError::RenewalPersisted(
                        request.profile_name.to_owned(),
                    )),
                    source,
                });
            }
            Ok(acquired_candidate(candidate))
        }
    }
}

enum PersistedCandidate {
    Saved(SaveCacheEntry),
    Renewed(ReplaceCacheEntry),
}

fn persist_candidate(
    cache_dir: &Path,
    cache_key: &str,
    renewal: Option<DerivedCacheEntry>,
    candidate: &CacheEntry,
    epoch: u64,
    expected_root: (&str, &str),
    received_at: OffsetDateTime,
) -> Result<PersistedCandidate, crate::cache::CacheError> {
    renewal.map_or_else(
        || {
            save_cache_candidate(cache_dir, cache_key, candidate, epoch, Some(expected_root))
                .map(PersistedCandidate::Saved)
        },
        |entry| {
            replace_cache_candidate(
                cache_dir,
                cache_key,
                &CacheEntry::Derived(entry),
                candidate,
                epoch,
                expected_root,
                received_at,
            )
            .map(PersistedCandidate::Renewed)
        },
    )
}

fn revoke_candidate<C: ScopedTokenClient>(
    client: &C,
    request: &AcquireRequest<'_>,
    client_id: &str,
    secret: &str,
    candidate: &CacheEntry,
) -> Result<(), TokenError> {
    client
        .delete_token(client_id, secret, candidate.access_token().as_ref())
        .map_err(|source| TokenError::RevocationFailed {
            context: Box::new(TokenError::StaleProvenance {
                profile: request.profile_name.to_owned(),
                reason: "a compatible concurrent cache winner retained the token",
            }),
            source,
        })
}

fn acquired_candidate(candidate: CacheEntry) -> AcquiredToken {
    match candidate {
        CacheEntry::Derived(entry) => acquired_derived(entry),
        CacheEntry::Root(_) | CacheEntry::Run(_) => unreachable!("candidate is derived"),
    }
}

fn acquired_retained(retained: CacheEntry) -> Result<AcquiredToken, TokenError> {
    match retained {
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

fn acquired_derived(entry: DerivedCacheEntry) -> AcquiredToken {
    AcquiredToken {
        access_token: entry.access_token,
        expires_at: entry.expires_at,
        profile: entry.profile,
        repo_scope: entry.repo_scope,
    }
}
