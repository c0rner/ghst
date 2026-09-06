use crate::credential::store::Inspect;
use crate::credential::store::SaveStoredCredential;
use crate::credential::stored::{
    StoredBase, StoredCredential, authority_fingerprint, compute_cache_key,
};
pub mod client;

use super::{
    BasePersistence, BaseTokenStatus, TokenError, revoke_with_context, validate_base_expiry,
};
use crate::profile::{AppAuthority, AppRegistration};
use crate::token::base::client::{BaseTokenClient, IssuedBaseToken};
use time::OffsetDateTime;

pub fn base_cache_key(profile_name: &str) -> String {
    compute_cache_key(profile_name, "all")
}

pub fn load_valid_base_entry<S: Inspect + ?Sized>(
    store: &S,
    profile_name: &str,
    authority: &AppAuthority<'_>,
    now: OffsetDateTime,
) -> Result<Option<StoredBase>, TokenError> {
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

pub fn load_valid_base_status<S: Inspect + ?Sized>(
    store: &S,
    profile_name: &str,
    authority: &AppAuthority<'_>,
    now: OffsetDateTime,
) -> Result<Option<BaseTokenStatus>, TokenError> {
    load_valid_base_entry(store, profile_name, authority, now).map(|entry| entry.map(base_status))
}

pub fn load_current_base_entry<S: Inspect + ?Sized>(
    store: &S,
    profile_name: &str,
    authority: &AppAuthority<'_>,
) -> Result<Option<StoredBase>, TokenError> {
    let key = base_cache_key(profile_name);
    let Some(entry) = store.load(&key)? else {
        tracing::debug!(
            profile = profile_name,
            cache_key = key,
            "base token cache miss"
        );
        return Ok(None);
    };
    if entry.profile() != profile_name {
        return Err(TokenError::InconsistentCacheMetadata {
            profile: profile_name.to_owned(),
            found: entry.profile().to_owned(),
        });
    }
    match entry {
        StoredCredential::Base(entry) => {
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
        other @ (StoredCredential::Scoped(_) | StoredCredential::Run(_)) => {
            Err(TokenError::UnexpectedCacheKind {
                profile: profile_name.to_owned(),
                expected: "base",
                actual: other.kind_name(),
            })
        }
    }
}

pub fn persist_base_response<C: BaseTokenClient, S: crate::credential::store::Login + ?Sized>(
    client: &C,
    app: &AppRegistration<'_>,
    profile_name: &str,
    store: &S,
    response: IssuedBaseToken,
    now: OffsetDateTime,
    epoch: u64,
) -> Result<BasePersistence, TokenError> {
    let IssuedBaseToken {
        access_token,
        expires_in,
    } = response;
    let expiry = match validate_base_expiry(expires_in, now) {
        Ok(expiry) => expiry,
        Err(error) => {
            tracing::debug!(profile = profile_name, error = %error, "issued base token had an invalid lifetime");
            return Err(revoke_with_context(client, app, &access_token, error));
        }
    };
    tracing::debug!(profile = profile_name, expires_at = %expiry, "validated issued base token lifetime");
    let user = match client.get_user(access_token.as_ref()) {
        Ok(user) => user,
        Err(error) => {
            tracing::debug!(profile = profile_name, error = %error, "failed to identify the GitHub user for issued base token");
            return Err(revoke_with_context(
                client,
                app,
                &access_token,
                TokenError::GitHub(error),
            ));
        }
    };
    let candidate = StoredCredential::Base(StoredBase {
        profile: profile_name.to_owned(),
        authority_fingerprint: authority_fingerprint(
            app.authority.client_id,
            app.authority.account,
        ),
        github_user: user.login,
        expires_at: expiry,
        access_token,
    });
    let StoredCredential::Base(base) = &candidate else {
        unreachable!("candidate is base")
    };
    let result = match store.commit_login(&base_cache_key(profile_name), base, epoch) {
        Ok(result) => result,
        Err(error) => {
            tracing::debug!(profile = profile_name, error = %error, "failed to persist issued base token");
            return Err(revoke_with_context(
                client,
                app,
                candidate.access_token(),
                TokenError::Cache(error),
            ));
        }
    };
    match result {
        SaveStoredCredential::Saved => match candidate {
            StoredCredential::Base(entry) => {
                tracing::debug!(profile = profile_name, "persisted issued base token");
                Ok(BasePersistence::Saved(base_status(entry)))
            }
            StoredCredential::Scoped(_) | StoredCredential::Run(_) => {
                unreachable!("candidate is base")
            }
        },
        SaveStoredCredential::Retained(entry) => match *entry {
            StoredCredential::Base(entry) => {
                tracing::debug!(
                    profile = profile_name,
                    "a compatible concurrent base token won the cache race; revoking unused candidate"
                );
                let cleanup = revoke_with_context(
                    client,
                    app,
                    candidate.access_token(),
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
            entry @ (StoredCredential::Scoped(_) | StoredCredential::Run(_)) => {
                Err(TokenError::UnexpectedCacheKind {
                    profile: profile_name.to_owned(),
                    expected: "base",
                    actual: entry.kind_name(),
                })
            }
        },
    }
}

fn base_status(entry: StoredBase) -> BaseTokenStatus {
    BaseTokenStatus {
        github_user: entry.github_user,
        expires_at: entry.expires_at,
    }
}
