use time::OffsetDateTime;

use super::{
    AcquireRequest, AcquiredToken, TokenError, load_valid_base_entry, revoke_with_context,
};
use crate::credential::store::{
    CommitScopedOutcome, IssuanceGuardStore, ReadCredentials, ReplaceOutcome, SourceGuard,
    WriteCredentials,
};
use crate::credential::{AccessToken, ScopedCredential, authority_fingerprint, policy_fingerprint};
use crate::domain::profile::AppAuthority;
use crate::token::ScopedTokenClient;

pub fn acquire<C, S, E>(
    client: &C,
    store: &S,
    request: AcquireRequest<'_>,
) -> Result<AcquiredToken, TokenError<E>>
where
    C: ScopedTokenClient,
    S: ReadCredentials<Error = E> + WriteCredentials<Error = E> + IssuanceGuardStore<Error = E>,
    E: std::error::Error + 'static,
{
    acquire_with_clock(client, store, request, OffsetDateTime::now_utc)
}

pub(super) fn acquire_with_clock<C, S, E, N>(
    client: &C,
    store: &S,
    request: AcquireRequest<'_>,
    mut now: N,
) -> Result<AcquiredToken, TokenError<E>>
where
    C: ScopedTokenClient,
    S: ReadCredentials<Error = E> + WriteCredentials<Error = E> + IssuanceGuardStore<Error = E>,
    E: std::error::Error + 'static,
    N: FnMut() -> OffsetDateTime,
{
    match request {
        AcquireRequest::Base {
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

fn acquire_base<S, E>(
    store: &S,
    profile_name: &str,
    authority: &AppAuthority<'_>,
    now: OffsetDateTime,
) -> Result<AcquiredToken, TokenError<E>>
where
    S: ReadCredentials<Error = E>,
    E: std::error::Error + 'static,
{
    let entry = load_valid_base_entry(store, profile_name, authority, now)?
        .ok_or_else(|| TokenError::NoBaseTokenCached(profile_name.to_owned()))?;
    tracing::debug!(
        profile = profile_name,
        expires_at = %entry.expires_at,
        "returning cached base token"
    );
    Ok(AcquiredToken {
        access_token: entry.access_token,
        expires_at: entry.expires_at,
        profile: profile_name.to_owned(),
        repo_scope: "all".to_owned(),
    })
}

fn acquire_scoped<C, S, E, N>(
    client: &C,
    store: &S,
    prepared: super::scoped::PreparedScopedToken<'_>,
    now: &mut N,
) -> Result<AcquiredToken, TokenError<E>>
where
    C: ScopedTokenClient,
    S: ReadCredentials<Error = E> + WriteCredentials<Error = E> + IssuanceGuardStore<Error = E>,
    E: std::error::Error + 'static,
    N: FnMut() -> OffsetDateTime,
{
    let policy = policy_fingerprint(
        prepared.app.authority.account,
        &prepared.scope,
        prepared.permissions,
    );
    tracing::debug!(
        profile = prepared.profile_name,
        source_profile = prepared.source_name,
        account = prepared.app.authority.account,
        repo_scope = prepared.scope,
        permissions = ?prepared.permissions,
        "prepared scoped token acquisition"
    );
    let provenance = ScopedProvenance {
        profile_name: prepared.profile_name,
        source_name: prepared.source_name,
        canonical_scope: &prepared.scope,
        policy: &policy,
        parent_generation: &prepared.base.generation_fingerprint(),
        source_authority: &prepared.app.authority,
    };
    let renewal = match classify_scoped_entry(store, &provenance, now())? {
        CachedScoped::Fresh(entry) => {
            tracing::debug!(
                profile = prepared.profile_name,
                expires_at = %entry.expires_at,
                "returning fresh cached scoped token"
            );
            return Ok(acquired_scoped(entry));
        }
        CachedScoped::Renewable(entry) => {
            tracing::debug!(
                profile = prepared.profile_name,
                expires_at = %entry.expires_at,
                "cached scoped token is in the renewal window"
            );
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
    Fresh(ScopedCredential),
    Renewable(ScopedCredential),
    MissingOrUnsafe,
}

fn classify_scoped_entry<S, E>(
    store: &S,
    provenance: &ScopedProvenance<'_>,
    now: OffsetDateTime,
) -> Result<CachedScoped, TokenError<E>>
where
    S: ReadCredentials<Error = E>,
    E: std::error::Error + 'static,
{
    let Some(entry) = store
        .read_scoped(provenance.profile_name, provenance.canonical_scope)
        .map_err(TokenError::Storage)?
    else {
        tracing::debug!(
            profile = provenance.profile_name,
            repo_scope = provenance.canonical_scope,
            "scoped token cache miss"
        );
        return Ok(CachedScoped::MissingOrUnsafe);
    };
    if entry.profile != provenance.profile_name {
        return Err(TokenError::InconsistentCacheMetadata {
            profile: provenance.profile_name.to_owned(),
            found: entry.profile,
        });
    }
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
            repo_scope = provenance.canonical_scope,
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

struct MintRequest<'a> {
    policy: &'a str,
    prepared: super::scoped::PreparedScopedToken<'a>,
    renewal: Option<ScopedCredential>,
}

fn mint_and_persist<C, S, E, N>(
    client: &C,
    store: &S,
    mint: MintRequest<'_>,
    now: &mut N,
) -> Result<AcquiredToken, TokenError<E>>
where
    C: ScopedTokenClient,
    S: WriteCredentials<Error = E> + IssuanceGuardStore<Error = E>,
    E: std::error::Error + 'static,
    N: FnMut() -> OffsetDateTime,
{
    let guard = store.issuance_guard().map_err(TokenError::Storage)?;
    let generation = mint.prepared.base.generation_fingerprint();
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
    let issued = super::scoped::issue(client, store, &mint.prepared, request_time, now)?;
    tracing::debug!(
        profile = mint.prepared.profile_name,
        expires_at = %issued.expires_at,
        "received valid scoped token from GitHub"
    );
    let candidate = ScopedCredential {
        profile: mint.prepared.profile_name.to_owned(),
        source_profile: mint.prepared.source_name.to_owned(),
        source_authority_fingerprint: authority_fingerprint(
            mint.prepared.app.authority.client_id,
            mint.prepared.app.authority.account,
        ),
        parent_generation: mint.prepared.base.generation_fingerprint(),
        policy_fingerprint: mint.policy.to_owned(),
        github_user: mint.prepared.base.github_user.clone(),
        repo_scope: mint.prepared.scope.clone(),
        expires_at: issued.expires_at,
        access_token: issued.access_token,
    };
    let source_guard = SourceGuard::new(mint.prepared.source_name, &generation);
    let persistence = match mint.renewal {
        None => store
            .commit_scoped(&candidate, guard, &source_guard)
            .map(PersistedCandidate::Saved),
        Some(ref expected) => store
            .renew_scoped(
                expected,
                &candidate,
                guard,
                &source_guard,
                issued.received_at,
            )
            .map(PersistedCandidate::Renewed),
    };
    let saved = match persistence {
        Ok(result) => result,
        Err(error) => {
            tracing::debug!(
                profile = mint.prepared.profile_name,
                error = %error,
                "failed to persist scoped token; revoking candidate"
            );
            return Err(revoke_with_context(
                client,
                &mint.prepared.app.as_registration(),
                &candidate.access_token,
                TokenError::Storage(error),
            ));
        }
    };
    finish_persisted_candidate(client, &mint.prepared, candidate, saved)
}

fn finish_persisted_candidate<C, E>(
    client: &C,
    prepared: &super::scoped::PreparedScopedToken<'_>,
    candidate: ScopedCredential,
    saved: PersistedCandidate,
) -> Result<AcquiredToken, TokenError<E>>
where
    C: ScopedTokenClient,
{
    let profile_name = prepared.profile_name;
    let source_name = prepared.source_name;
    let client_id = prepared.app.authority.client_id;
    let secret = prepared.app.client_secret;
    let registration = prepared.app.as_registration();
    match saved {
        PersistedCandidate::Saved(CommitScopedOutcome::Saved) => {
            tracing::debug!(profile = profile_name, "persisted new scoped token");
            Ok(acquired_scoped(candidate))
        }
        PersistedCandidate::Saved(CommitScopedOutcome::Retained(retained)) => {
            tracing::debug!(
                profile = profile_name,
                "compatible concurrent scoped token won the cache race; revoking unused candidate"
            );
            revoke_candidate(
                client,
                profile_name,
                client_id,
                secret,
                &candidate.access_token,
            )?;
            Ok(acquired_scoped(*retained))
        }
        PersistedCandidate::Renewed(ReplaceOutcome::Retained(retained)) => {
            tracing::debug!(
                profile = profile_name,
                "compatible concurrent scoped token won the cache race; revoking unused candidate"
            );
            revoke_candidate(
                client,
                profile_name,
                client_id,
                secret,
                &candidate.access_token,
            )?;
            Ok(acquired_scoped(retained))
        }
        PersistedCandidate::Renewed(ReplaceOutcome::Replaced(displaced)) => {
            tracing::debug!(
                profile = profile_name,
                "persisted renewed scoped token; revoking displaced token"
            );
            if let Err(source) =
                client.delete_token(client_id, secret, displaced.access_token.as_ref())
            {
                return Err(TokenError::RevocationFailed {
                    context: Box::new(TokenError::RenewalPersisted(profile_name.to_owned())),
                    source,
                });
            }
            Ok(acquired_scoped(candidate))
        }
        PersistedCandidate::Saved(CommitScopedOutcome::EpochChanged)
        | PersistedCandidate::Renewed(ReplaceOutcome::EpochChanged) => {
            tracing::debug!(
                profile = profile_name,
                "cache epoch changed while persisting scoped token; revoking candidate"
            );
            Err(revoke_with_context(
                client,
                &registration,
                &candidate.access_token,
                TokenError::EpochChanged(profile_name.to_owned()),
            ))
        }
        PersistedCandidate::Saved(CommitScopedOutcome::BaseGenerationChanged)
        | PersistedCandidate::Renewed(ReplaceOutcome::BaseGenerationChanged) => {
            tracing::debug!(
                profile = profile_name,
                "base token generation changed while persisting scoped token; revoking candidate"
            );
            Err(revoke_with_context(
                client,
                &registration,
                &candidate.access_token,
                TokenError::BaseGenerationChanged(source_name.to_owned()),
            ))
        }
        PersistedCandidate::Renewed(ReplaceOutcome::RenewalEntryChanged) => {
            tracing::debug!(
                profile = profile_name,
                "cached scoped token changed while renewing; revoking candidate"
            );
            Err(revoke_with_context(
                client,
                &registration,
                &candidate.access_token,
                TokenError::RenewalEntryChanged(profile_name.to_owned()),
            ))
        }
    }
}

enum PersistedCandidate {
    Saved(CommitScopedOutcome),
    Renewed(ReplaceOutcome<ScopedCredential>),
}

fn revoke_candidate<C: ScopedTokenClient, E>(
    client: &C,
    profile_name: &str,
    client_id: &str,
    secret: &str,
    token: &AccessToken,
) -> Result<(), TokenError<E>> {
    client
        .delete_token(client_id, secret, token.as_ref())
        .map_err(|source| TokenError::RevocationFailed {
            context: Box::new(TokenError::StaleProvenance {
                profile: profile_name.to_owned(),
                reason: "a compatible concurrent cache winner retained the token",
            }),
            source,
        })
}

fn acquired_scoped(entry: ScopedCredential) -> AcquiredToken {
    AcquiredToken {
        access_token: entry.access_token,
        expires_at: entry.expires_at,
        profile: entry.profile,
        repo_scope: entry.repo_scope,
    }
}
