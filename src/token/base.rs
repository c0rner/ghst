use super::{
    BasePersistence, BaseTokenStatus, TokenError, revoke_with_context, validate_base_expiry,
};
use crate::credential::store::{IssuanceGuard, ReadCredentials, SaveOutcome, WriteCredentials};
use crate::credential::{BaseCredential, authority_fingerprint};
use crate::domain::profile::{AppAuthority, AppRegistration};
use crate::token::{BaseTokenClient, IssuedBaseToken};
use time::OffsetDateTime;

pub fn base_cache_key(profile_name: &str) -> String {
    crate::cache::compute_cache_key(profile_name, "all")
}

pub fn load_valid_base_entry<S, E>(
    store: &S,
    profile_name: &str,
    authority: &AppAuthority<'_>,
    now: OffsetDateTime,
) -> Result<Option<BaseCredential>, TokenError<E>>
where
    S: ReadCredentials<Error = E>,
    E: std::error::Error + 'static,
{
    let entry = load_current_base_entry(store, profile_name, authority)?;
    match entry {
        Some(entry) if entry.expires_at.is_safe_to_handoff_at(now) => {
            tracing::debug!(
                profile = profile_name,
                expires_at = %entry.expires_at,
                "cached base token is safe to use"
            );
            Ok(Some(entry))
        }
        Some(entry) => {
            tracing::debug!(
                profile = profile_name,
                expires_at = %entry.expires_at,
                "cached base token is inside the handoff safety margin"
            );
            Ok(None)
        }
        None => Ok(None),
    }
}

pub fn load_valid_base_status<S, E>(
    store: &S,
    profile_name: &str,
    authority: &AppAuthority<'_>,
    now: OffsetDateTime,
) -> Result<Option<BaseTokenStatus>, TokenError<E>>
where
    S: ReadCredentials<Error = E>,
    E: std::error::Error + 'static,
{
    load_valid_base_entry(store, profile_name, authority, now).map(|entry| entry.map(base_status))
}

pub fn load_current_base_entry<S, E>(
    store: &S,
    profile_name: &str,
    authority: &AppAuthority<'_>,
) -> Result<Option<BaseCredential>, TokenError<E>>
where
    S: ReadCredentials<Error = E>,
    E: std::error::Error + 'static,
{
    let Some(entry) = store.read_base(profile_name).map_err(TokenError::Storage)? else {
        tracing::debug!(profile = profile_name, "base token cache miss");
        return Ok(None);
    };
    if entry.profile != profile_name {
        return Err(TokenError::InconsistentCacheMetadata {
            profile: profile_name.to_owned(),
            found: entry.profile,
        });
    }
    if !super::provenance::matches_authority(authority, &entry.authority_fingerprint) {
        tracing::debug!(
            profile = profile_name,
            account = authority.account,
            client_id = authority.client_id,
            "cached base token was rejected because its configured authority changed"
        );
        return Ok(None);
    }
    tracing::debug!(
        profile = profile_name,
        github_user = entry.github_user,
        expires_at = %entry.expires_at,
        "base token cache hit"
    );
    Ok(Some(entry))
}

pub fn persist_base_response<C, S, E>(
    client: &C,
    app: &AppRegistration<'_>,
    profile_name: &str,
    store: &S,
    response: IssuedBaseToken,
    now: OffsetDateTime,
    guard: IssuanceGuard,
) -> Result<BasePersistence, TokenError<E>>
where
    C: BaseTokenClient,
    S: WriteCredentials<Error = E>,
    E: std::error::Error + 'static,
{
    let IssuedBaseToken {
        access_token,
        expires_in,
    } = response;
    let expiry = match validate_base_expiry(expires_in, now) {
        Ok(expiry) => expiry,
        Err(error) => {
            tracing::debug!(
                profile = profile_name,
                error = %error,
                "issued base token had an invalid lifetime"
            );
            return Err(revoke_with_context(client, app, &access_token, error));
        }
    };
    tracing::debug!(
        profile = profile_name,
        expires_at = %expiry,
        "validated issued base token lifetime"
    );
    let user = match client.get_user(access_token.as_ref()) {
        Ok(user) => user,
        Err(error) => {
            tracing::debug!(
                profile = profile_name,
                error = %error,
                "failed to identify the GitHub user for issued base token"
            );
            return Err(revoke_with_context(
                client,
                app,
                &access_token,
                TokenError::GitHub(error),
            ));
        }
    };
    let candidate = BaseCredential {
        profile: profile_name.to_owned(),
        authority_fingerprint: authority_fingerprint(
            app.authority.client_id,
            app.authority.account,
        ),
        github_user: user.login,
        expires_at: expiry,
        access_token,
    };
    let result = match store.commit_base(&candidate, guard) {
        Ok(result) => result,
        Err(error) => {
            tracing::debug!(
                profile = profile_name,
                error = %error,
                "failed to persist issued base token"
            );
            return Err(revoke_with_context(
                client,
                app,
                &candidate.access_token,
                TokenError::Storage(error),
            ));
        }
    };
    handle_save_outcome(client, app, candidate, result)
}

fn handle_save_outcome<C: BaseTokenClient, E>(
    client: &C,
    app: &AppRegistration<'_>,
    candidate: BaseCredential,
    result: SaveOutcome<BaseCredential>,
) -> Result<BasePersistence, TokenError<E>> {
    let profile_name = &candidate.profile;
    match result {
        SaveOutcome::Saved => {
            tracing::debug!(profile = profile_name, "persisted issued base token");
            Ok(BasePersistence::Saved(base_status(candidate)))
        }
        SaveOutcome::Retained(entry) => {
            tracing::debug!(
                profile = profile_name,
                "a compatible concurrent base token won the cache race; revoking unused candidate"
            );
            let cleanup = revoke_with_context(
                client,
                app,
                &candidate.access_token,
                TokenError::StaleProvenance {
                    profile: profile_name.to_owned(),
                    reason: "a compatible concurrent base cache winner was retained",
                },
            );
            if matches!(cleanup, TokenError::RevocationFailed { .. }) {
                Err(cleanup)
            } else {
                Ok(BasePersistence::Retained(base_status(entry)))
            }
        }
        SaveOutcome::EpochChanged => {
            tracing::debug!(
                profile = profile_name,
                "cache epoch changed while issuing base token; revoking unused candidate"
            );
            Err(revoke_with_context(
                client,
                app,
                &candidate.access_token,
                TokenError::EpochChanged(profile_name.to_owned()),
            ))
        }
        SaveOutcome::BaseGenerationChanged => {
            tracing::debug!(
                profile = profile_name,
                "base generation changed while issuing base token; revoking unused candidate"
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

fn base_status(entry: BaseCredential) -> BaseTokenStatus {
    BaseTokenStatus {
        github_user: entry.github_user,
        expires_at: entry.expires_at,
    }
}
