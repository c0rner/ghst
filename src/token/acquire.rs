use crate::credential::provenance::ScopedProvenance;
use crate::credential::store::{ExpectedSource, Inspect, IssuanceGuard, Issue, Remove, StoreError};
use crate::credential::store::{ReplaceStoredCredential, SaveStoredCredential};
use crate::credential::stored::{
    StoredCredential, StoredScoped, compute_cache_key, policy_fingerprint,
};
use time::OffsetDateTime;

use super::{
    AcquireRequest, AcquiredToken, TokenError, base_cache_key, load_valid_base_entry,
    revoke_with_context,
};
use crate::profile::AppAuthority;
use crate::token::scoped::client::ScopedTokenClient;

pub fn acquire<C: ScopedTokenClient, S: Inspect + Issue + Remove + ?Sized>(
    client: &C,
    request: AcquireRequest<'_, S>,
) -> Result<AcquiredToken, TokenError> {
    acquire_with_clock(client, request, OffsetDateTime::now_utc)
}

pub(super) fn acquire_with_clock<
    C: ScopedTokenClient,
    N: FnMut() -> OffsetDateTime,
    S: Inspect + Issue + Remove + ?Sized,
>(
    client: &C,
    request: AcquireRequest<'_, S>,
    mut now: N,
) -> Result<AcquiredToken, TokenError> {
    match request {
        AcquireRequest::Base {
            store,
            profile_name,
            authority,
        } => {
            tracing::debug!(
                profile = profile_name,
                profile_kind = "app",
                "starting token acquisition"
            );
            acquire_base(store, profile_name, &authority, now())
        }
        AcquireRequest::Scoped {
            store,
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
                store,
                profile_name,
                source_name,
                app,
                permissions,
                &repositories,
            )?;
            acquire_scoped(client, store, prepared, &mut now)
        }
    }
}

fn acquire_base<S: Inspect + ?Sized>(
    store: &S,
    profile_name: &str,
    authority: &AppAuthority<'_>,
    now: OffsetDateTime,
) -> Result<AcquiredToken, TokenError> {
    let entry = load_valid_base_entry(store, profile_name, authority, now)?
        .ok_or_else(|| TokenError::NoBaseTokenCached(profile_name.to_owned()))?;
    tracing::debug!(profile = profile_name, expires_at = %entry.expires_at, "returning cached base token");
    Ok(AcquiredToken {
        access_token: entry.access_token,
        expires_at: entry.expires_at,
        profile: profile_name.to_owned(),
        repo_scope: "all".to_owned(),
    })
}

fn acquire_scoped<
    C: ScopedTokenClient,
    N: FnMut() -> OffsetDateTime,
    S: Inspect + Issue + Remove + ?Sized,
>(
    client: &C,
    store: &S,
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
    let source_authority = crate::credential::stored::authority_fingerprint(
        prepared.app.authority.client_id,
        prepared.app.authority.account,
    );
    let provenance = ScopedProvenance {
        profile: prepared.profile_name,
        source_profile: prepared.source_name,
        repo_scope: &prepared.scope,
        policy: &policy,
        parent_generation: &generation,
        source_authority: &source_authority,
    };
    let renewal = match classify_scoped_entry(store, &cache_key, &provenance, now())? {
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
        store,
        MintRequest {
            cache_key: &cache_key,
            policy: &policy,
            prepared,
            renewal,
        },
        now,
    )
}

enum CachedScoped {
    Fresh(StoredScoped),
    Renewable(StoredScoped),
    MissingOrUnsafe,
}

fn classify_scoped_entry<S: Inspect + ?Sized>(
    store: &S,
    cache_key: &str,
    provenance: &ScopedProvenance<'_>,
    now: OffsetDateTime,
) -> Result<CachedScoped, TokenError> {
    let Some(entry) = store.load(cache_key)? else {
        tracing::debug!(
            profile = provenance.profile,
            cache_key,
            "scoped token cache miss"
        );
        return Ok(CachedScoped::MissingOrUnsafe);
    };
    if entry.profile() != provenance.profile {
        return Err(TokenError::InconsistentCacheMetadata {
            profile: provenance.profile.to_owned(),
            found: entry.profile().to_owned(),
        });
    }
    match entry {
        StoredCredential::Scoped(entry) => {
            let rejection = entry.provenance().mismatch(provenance).or_else(|| {
                (!entry.expires_at.is_safe_to_handoff_at(now))
                    .then_some("token is expired or inside the handoff safety margin")
            });
            if let Some(reason) = rejection {
                tracing::debug!(
                    profile = provenance.profile,
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
        other @ (StoredCredential::Base(_) | StoredCredential::Run(_)) => {
            Err(TokenError::UnexpectedCacheKind {
                profile: provenance.profile.to_owned(),
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
    renewal: Option<StoredScoped>,
}

fn mint_and_persist<
    C: ScopedTokenClient,
    N: FnMut() -> OffsetDateTime,
    S: Issue + Remove + ?Sized,
>(
    client: &C,
    store: &S,
    mint: MintRequest<'_>,
    now: &mut N,
) -> Result<AcquiredToken, TokenError> {
    let epoch = store.epoch()?;
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
    {
        if let Some(entry) = mint.renewal {
            if entry.expires_at.is_safe_to_handoff_at(request_time) {
                tracing::debug!(
                    profile = mint.prepared.profile_name,
                    base_expires_at = %mint.prepared.base.expires_at,
                    scoped_expires_at = %entry.expires_at,
                    "base token cannot safely mint a replacement; returning provenance-valid cached scoped token"
                );
                return Ok(acquired_scoped(entry));
            }
            tracing::debug!(
                profile = mint.prepared.profile_name,
                base_expires_at = %mint.prepared.base.expires_at,
                scoped_expires_at = %entry.expires_at,
                "base token cannot safely mint a replacement and cached scoped token is inside the handoff safety margin"
            );
        }
        return Err(TokenError::NoSourceBaseTokenCached(
            mint.prepared.source_name.to_owned(),
        ));
    }
    let issued = super::scoped::issue(client, &mint.prepared, store, request_time, now)?;
    tracing::debug!(profile = mint.prepared.profile_name, expires_at = %issued.expires_at, "received valid scoped token from GitHub");
    let candidate = StoredCredential::Scoped(StoredScoped {
        profile: mint.prepared.profile_name.to_owned(),
        source_profile: mint.prepared.source_name.to_owned(),
        source_authority_fingerprint: crate::credential::stored::authority_fingerprint(
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
        store,
        mint.cache_key,
        mint.renewal,
        &candidate,
        epoch,
        (&base_key, &generation),
        issued.received_at,
    );
    let saved = match persistence {
        Ok(result) => result,
        Err(StoreError::BaseGenerationChanged) => {
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
    candidate: StoredCredential,
    saved: PersistedCandidate,
) -> Result<AcquiredToken, TokenError> {
    match saved {
        PersistedCandidate::Saved(SaveStoredCredential::Saved) => {
            tracing::debug!(profile = profile_name, "persisted new scoped token");
            Ok(acquired_candidate(candidate))
        }
        PersistedCandidate::Saved(SaveStoredCredential::Retained(retained))
        | PersistedCandidate::Renewed(ReplaceStoredCredential::Retained(retained)) => {
            tracing::debug!(
                profile = profile_name,
                "compatible concurrent scoped token won the cache race; revoking unused candidate"
            );
            revoke_candidate(client, profile_name, client_id, secret, &candidate)?;
            acquired_retained(*retained)
        }
        PersistedCandidate::Renewed(ReplaceStoredCredential::Replaced(displaced)) => {
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
    Saved(SaveStoredCredential),
    Renewed(ReplaceStoredCredential),
}

fn persist_candidate<S: Issue + ?Sized>(
    store: &S,
    cache_key: &str,
    renewal: Option<StoredScoped>,
    candidate: &StoredCredential,
    epoch: u64,
    expected_base: (&str, &str),
    received_at: OffsetDateTime,
) -> Result<PersistedCandidate, StoreError> {
    renewal.map_or_else(
        || {
            store
                .commit(
                    cache_key,
                    candidate,
                    IssuanceGuard {
                        epoch,
                        source: ExpectedSource {
                            key: expected_base.0,
                            generation: expected_base.1,
                        },
                    },
                )
                .map(PersistedCandidate::Saved)
        },
        |entry| {
            store
                .renew(
                    cache_key,
                    &StoredCredential::Scoped(entry),
                    candidate,
                    IssuanceGuard {
                        epoch,
                        source: ExpectedSource {
                            key: expected_base.0,
                            generation: expected_base.1,
                        },
                    },
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
    candidate: &StoredCredential,
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

fn acquired_candidate(candidate: StoredCredential) -> AcquiredToken {
    match candidate {
        StoredCredential::Scoped(entry) => acquired_scoped(entry),
        StoredCredential::Base(_) | StoredCredential::Run(_) => unreachable!("candidate is scoped"),
    }
}

fn acquired_retained(retained: StoredCredential) -> Result<AcquiredToken, TokenError> {
    match retained {
        StoredCredential::Scoped(entry) => Ok(acquired_scoped(entry)),
        other @ (StoredCredential::Base(_) | StoredCredential::Run(_)) => {
            Err(TokenError::UnexpectedCacheKind {
                profile: other.profile().to_owned(),
                expected: "scoped",
                actual: other.kind_name(),
            })
        }
    }
}

fn acquired_scoped(entry: StoredScoped) -> AcquiredToken {
    AcquiredToken {
        access_token: entry.access_token,
        expires_at: entry.expires_at,
        profile: entry.profile,
        repo_scope: entry.repo_scope,
    }
}
