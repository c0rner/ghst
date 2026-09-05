use std::path::Path;
use time::OffsetDateTime;

use super::{
    AcquireRequest, AcquiredToken, TokenError, base_cache_key, load_valid_base_entry,
    revoke_with_context,
};
use crate::cache::{
    CACHE_SCHEMA_VERSION, CacheEntry, ReplaceCacheEntry, SaveCacheEntry, ScopedCacheEntry,
    cache_epoch, compute_cache_key, load_cache_entry, policy_fingerprint, replace_cache_candidate,
    save_cache_candidate,
};
use crate::domain::profile::AppAuthority;
use crate::token::ScopedTokenClient;

pub fn acquire<C: ScopedTokenClient>(
    client: &C,
    request: AcquireRequest<'_>,
) -> Result<AcquiredToken, TokenError> {
    acquire_with_clock(client, request, OffsetDateTime::now_utc)
}

pub(super) fn acquire_with_clock<C: ScopedTokenClient, N: FnMut() -> OffsetDateTime>(
    client: &C,
    request: AcquireRequest<'_>,
    mut now: N,
) -> Result<AcquiredToken, TokenError> {
    match request {
        AcquireRequest::Base {
            cache_dir,
            profile_name,
            authority,
        } => {
            tracing::debug!(
                profile = profile_name,
                profile_kind = "app",
                "starting token acquisition"
            );
            acquire_base(cache_dir, profile_name, &authority, now())
        }
        AcquireRequest::Scoped {
            cache_dir,
            profile_name,
            source_name,
            app,
            permissions,
            repositories,
        } => {
            tracing::debug!(
                profile = profile_name,
                source_profile = source_name,
                profile_kind = "scoped",
                "starting token acquisition"
            );
            let prepared = super::scoped::prepare(
                cache_dir,
                profile_name,
                source_name,
                app,
                permissions,
                &repositories,
            )?;
            acquire_scoped(client, cache_dir, prepared, &mut now)
        }
    }
}

fn acquire_base(
    cache_dir: &Path,
    profile_name: &str,
    authority: &AppAuthority<'_>,
    now: OffsetDateTime,
) -> Result<AcquiredToken, TokenError> {
    let entry = load_valid_base_entry(cache_dir, profile_name, authority, now)?
        .ok_or_else(|| TokenError::NoBaseTokenCached(profile_name.to_owned()))?;
    tracing::debug!(profile = profile_name, expires_at = %entry.expires_at, "returning cached base token");
    Ok(AcquiredToken {
        access_token: entry.access_token,
        expires_at: entry.expires_at,
        profile: profile_name.to_owned(),
        repo_scope: "all".to_owned(),
    })
}

fn acquire_scoped<C: ScopedTokenClient, N: FnMut() -> OffsetDateTime>(
    client: &C,
    cache_dir: &Path,
    prepared: super::scoped::PreparedScopedToken<'_>,
    now: &mut N,
) -> Result<AcquiredToken, TokenError> {
    let policy = policy_fingerprint(
        prepared.app.authority.account,
        &prepared.scope,
        prepared.permissions,
    );
    let generation = prepared.base.generation_fingerprint();
    let cache_key = compute_cache_key(prepared.profile_name, &prepared.scope);
    tracing::debug!(
        profile = prepared.profile_name,
        source_profile = prepared.source_name,
        account = prepared.app.authority.account,
        repo_scope = prepared.scope,
        permissions = ?prepared.permissions,
        cache_key,
        "prepared scoped token acquisition"
    );
    let provenance = ScopedProvenance {
        profile_name: prepared.profile_name,
        source_name: prepared.source_name,
        canonical_scope: &prepared.scope,
        policy: &policy,
        parent_generation: &generation,
        source_authority: &prepared.app.authority,
    };
    let renewal = match classify_scoped_entry(cache_dir, &cache_key, &provenance, now())? {
        CachedScoped::Fresh(entry) => {
            tracing::debug!(profile = prepared.profile_name, expires_at = %entry.expires_at, "returning fresh cached scoped token");
            return Ok(acquired_scoped(entry));
        }
        CachedScoped::Renewable(entry) => {
            tracing::debug!(profile = prepared.profile_name, expires_at = %entry.expires_at, "cached scoped token is in the renewal window");
            Some(entry)
        }
        CachedScoped::MissingOrUnsafe => {
            tracing::debug!(
                profile = prepared.profile_name,
                "no reusable scoped token is cached; a new token is required"
            );
            None
        }
    };
    mint_and_persist(
        client,
        cache_dir,
        MintRequest {
            cache_key: &cache_key,
            policy: &policy,
            prepared,
            renewal,
        },
        now,
    )
}

struct ScopedProvenance<'a> {
    profile_name: &'a str,
    source_name: &'a str,
    canonical_scope: &'a str,
    policy: &'a str,
    parent_generation: &'a str,
    source_authority: &'a AppAuthority<'a>,
}

enum CachedScoped {
    Fresh(ScopedCacheEntry),
    Renewable(ScopedCacheEntry),
    MissingOrUnsafe,
}

fn classify_scoped_entry(
    cache_dir: &Path,
    cache_key: &str,
    provenance: &ScopedProvenance<'_>,
    now: OffsetDateTime,
) -> Result<CachedScoped, TokenError> {
    let Some(entry) = load_cache_entry(cache_dir, cache_key)? else {
        tracing::debug!(
            profile = provenance.profile_name,
            cache_key,
            "scoped token cache miss"
        );
        return Ok(CachedScoped::MissingOrUnsafe);
    };
    if entry.profile() != provenance.profile_name {
        return Err(TokenError::InconsistentCacheMetadata {
            profile: provenance.profile_name.to_owned(),
            found: entry.profile().to_owned(),
        });
    }
    match entry {
        CacheEntry::Scoped(entry) => {
            let rejection = if entry.source_profile != provenance.source_name {
                Some("source profile changed")
            } else if !super::provenance::matches_authority(
                provenance.source_authority,
                &entry.source_authority_fingerprint,
            ) {
                Some("source GitHub App authority changed")
            } else if entry.repo_scope != provenance.canonical_scope {
                Some("repository scope changed")
            } else if entry.policy_fingerprint != provenance.policy {
                Some("permissions or target account changed")
            } else if entry.parent_generation != provenance.parent_generation {
                Some("parent base token generation changed")
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
                    "cached scoped token was rejected"
                );
                Ok(CachedScoped::MissingOrUnsafe)
            } else if entry.expires_at.is_due_for_renewal_at(now) {
                Ok(CachedScoped::Renewable(entry))
            } else {
                Ok(CachedScoped::Fresh(entry))
            }
        }
        other @ (CacheEntry::Base(_) | CacheEntry::Run(_)) => {
            Err(TokenError::UnexpectedCacheKind {
                profile: provenance.profile_name.to_owned(),
                expected: "scoped",
                actual: other.kind_name(),
            })
        }
    }
}

struct MintRequest<'a> {
    cache_key: &'a str,
    policy: &'a str,
    prepared: super::scoped::PreparedScopedToken<'a>,
    renewal: Option<ScopedCacheEntry>,
}

fn mint_and_persist<C: ScopedTokenClient, N: FnMut() -> OffsetDateTime>(
    client: &C,
    cache_dir: &Path,
    mint: MintRequest<'_>,
    now: &mut N,
) -> Result<AcquiredToken, TokenError> {
    let epoch = cache_epoch(cache_dir)?;
    let generation = mint.prepared.base.generation_fingerprint();
    let secret = mint.prepared.app.client_secret;
    tracing::debug!(
        profile = mint.prepared.profile_name,
        source_profile = mint.prepared.source_name,
        repo_scope = mint.prepared.scope,
        renewal = mint.renewal.is_some(),
        "minting scoped token"
    );
    let request_time = now();
    if !mint
        .prepared
        .base
        .expires_at
        .is_safe_to_handoff_at(request_time)
        && let Some(entry) = mint.renewal
    {
        tracing::debug!(
            profile = mint.prepared.profile_name,
            base_expires_at = %mint.prepared.base.expires_at,
            scoped_expires_at = %entry.expires_at,
            "base token cannot safely mint a replacement; returning provenance-valid cached scoped token"
        );
        return Ok(acquired_scoped(entry));
    }
    let issued = super::scoped::issue(client, &mint.prepared, cache_dir, request_time, now)?;
    tracing::debug!(profile = mint.prepared.profile_name, expires_at = %issued.expires_at, "received valid scoped token from GitHub");
    let candidate = CacheEntry::Scoped(ScopedCacheEntry {
        version: CACHE_SCHEMA_VERSION,
        profile: mint.prepared.profile_name.to_owned(),
        source_profile: mint.prepared.source_name.to_owned(),
        source_authority_fingerprint: crate::cache::authority_fingerprint(
            mint.prepared.app.authority.client_id,
            mint.prepared.app.authority.account,
        ),
        parent_generation: mint.prepared.base.generation_fingerprint(),
        policy_fingerprint: mint.policy.to_owned(),
        github_user: mint.prepared.base.github_user,
        repo_scope: mint.prepared.scope.clone(),
        expires_at: issued.expires_at,
        access_token: issued.access_token,
    });
    let base_key = base_cache_key(mint.prepared.source_name);
    let persistence = persist_candidate(
        cache_dir,
        mint.cache_key,
        mint.renewal,
        &candidate,
        epoch,
        (&base_key, &generation),
        issued.received_at,
    );
    let saved = match persistence {
        Ok(result) => result,
        Err(crate::cache::CacheError::BaseGenerationChanged) => {
            tracing::debug!(
                profile = mint.prepared.profile_name,
                "base token generation changed while persisting scoped token; revoking candidate"
            );
            return Err(revoke_with_context(
                client,
                &mint.prepared.app.as_registration(),
                candidate.access_token(),
                TokenError::BaseGenerationChanged(mint.prepared.source_name.to_owned()),
            ));
        }
        Err(error) => {
            tracing::debug!(profile = mint.prepared.profile_name, error = %error, "failed to persist scoped token; revoking candidate");
            return Err(revoke_with_context(
                client,
                &mint.prepared.app.as_registration(),
                candidate.access_token(),
                TokenError::Cache(error),
            ));
        }
    };
    finish_persisted_candidate(
        client,
        mint.prepared.profile_name,
        mint.prepared.app.authority.client_id,
        secret,
        candidate,
        saved,
    )
}

fn finish_persisted_candidate<C: ScopedTokenClient>(
    client: &C,
    profile_name: &str,
    client_id: &str,
    secret: &str,
    candidate: CacheEntry,
    saved: PersistedCandidate,
) -> Result<AcquiredToken, TokenError> {
    match saved {
        PersistedCandidate::Saved(SaveCacheEntry::Saved) => {
            tracing::debug!(profile = profile_name, "persisted new scoped token");
            Ok(acquired_candidate(candidate))
        }
        PersistedCandidate::Saved(SaveCacheEntry::Retained(retained))
        | PersistedCandidate::Renewed(ReplaceCacheEntry::Retained(retained)) => {
            tracing::debug!(
                profile = profile_name,
                "compatible concurrent scoped token won the cache race; revoking unused candidate"
            );
            revoke_candidate(client, profile_name, client_id, secret, &candidate)?;
            acquired_retained(*retained)
        }
        PersistedCandidate::Renewed(ReplaceCacheEntry::Replaced(displaced)) => {
            tracing::debug!(
                profile = profile_name,
                "persisted renewed scoped token; revoking displaced token"
            );
            if let Err(source) =
                client.delete_token(client_id, secret, displaced.access_token().as_ref())
            {
                return Err(TokenError::RevocationFailed {
                    context: Box::new(TokenError::RenewalPersisted(profile_name.to_owned())),
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
    renewal: Option<ScopedCacheEntry>,
    candidate: &CacheEntry,
    epoch: u64,
    expected_base: (&str, &str),
    received_at: OffsetDateTime,
) -> Result<PersistedCandidate, crate::cache::CacheError> {
    renewal.map_or_else(
        || {
            save_cache_candidate(cache_dir, cache_key, candidate, epoch, Some(expected_base))
                .map(PersistedCandidate::Saved)
        },
        |entry| {
            replace_cache_candidate(
                cache_dir,
                cache_key,
                &CacheEntry::Scoped(entry),
                candidate,
                epoch,
                expected_base,
                received_at,
            )
            .map(PersistedCandidate::Renewed)
        },
    )
}

fn revoke_candidate<C: ScopedTokenClient>(
    client: &C,
    profile_name: &str,
    client_id: &str,
    secret: &str,
    candidate: &CacheEntry,
) -> Result<(), TokenError> {
    client
        .delete_token(client_id, secret, candidate.access_token().as_ref())
        .map_err(|source| TokenError::RevocationFailed {
            context: Box::new(TokenError::StaleProvenance {
                profile: profile_name.to_owned(),
                reason: "a compatible concurrent cache winner retained the token",
            }),
            source,
        })
}

fn acquired_candidate(candidate: CacheEntry) -> AcquiredToken {
    match candidate {
        CacheEntry::Scoped(entry) => acquired_scoped(entry),
        CacheEntry::Base(_) | CacheEntry::Run(_) => unreachable!("candidate is scoped"),
    }
}

fn acquired_retained(retained: CacheEntry) -> Result<AcquiredToken, TokenError> {
    match retained {
        CacheEntry::Scoped(entry) => Ok(acquired_scoped(entry)),
        other @ (CacheEntry::Base(_) | CacheEntry::Run(_)) => {
            Err(TokenError::UnexpectedCacheKind {
                profile: other.profile().to_owned(),
                expected: "scoped",
                actual: other.kind_name(),
            })
        }
    }
}

fn acquired_scoped(entry: ScopedCacheEntry) -> AcquiredToken {
    AcquiredToken {
        access_token: entry.access_token,
        expires_at: entry.expires_at,
        profile: entry.profile,
        repo_scope: entry.repo_scope,
    }
}
