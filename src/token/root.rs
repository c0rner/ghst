use super::{
    RootPersistence, RootTokenStatus, TokenError, revoke_with_context, validate_root_expiry,
};
use crate::cache::{
    CACHE_SCHEMA_VERSION, CacheEntry, RootCacheEntry, SaveCacheEntry, authority_fingerprint,
    compute_cache_key, load_cache_entry, save_cache_candidate,
};
use crate::config::{GitHubAppConfig, RootProfile};
use crate::token::{IssuedRootToken, RootTokenClient};
use std::path::Path;
use time::OffsetDateTime;

pub fn root_cache_key(profile_name: &str) -> String {
    compute_cache_key(profile_name, "all")
}

pub fn load_valid_root_entry(
    cache_dir: &Path,
    profile_name: &str,
    profile: &RootProfile,
    now: OffsetDateTime,
) -> Result<Option<RootCacheEntry>, TokenError> {
    let entry = load_current_root_entry(cache_dir, profile_name, &profile.github_app)?;
    match entry {
        Some(entry) if entry.expires_at.is_safe_to_handoff_at(now) => {
            tracing::debug!(
                profile = profile_name,
                expires_at = %entry.expires_at,
                "cached root token is safe to use"
            );
            Ok(Some(entry))
        }
        Some(entry) => {
            tracing::debug!(
                profile = profile_name,
                expires_at = %entry.expires_at,
                "cached root token is inside the handoff safety margin"
            );
            Ok(None)
        }
        None => Ok(None),
    }
}

pub fn load_valid_root_status(
    cache_dir: &Path,
    profile_name: &str,
    profile: &RootProfile,
    now: OffsetDateTime,
) -> Result<Option<RootTokenStatus>, TokenError> {
    load_valid_root_entry(cache_dir, profile_name, profile, now).map(|entry| entry.map(root_status))
}

pub fn load_current_root_entry(
    cache_dir: &Path,
    profile_name: &str,
    github_app: &GitHubAppConfig,
) -> Result<Option<RootCacheEntry>, TokenError> {
    let key = root_cache_key(profile_name);
    let Some(entry) = load_cache_entry(cache_dir, &key)? else {
        tracing::debug!(
            profile = profile_name,
            cache_key = key,
            "root token cache miss"
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
        CacheEntry::Root(entry) => {
            if entry.version != CACHE_SCHEMA_VERSION {
                tracing::debug!(
                    profile = profile_name,
                    cached_version = entry.version,
                    expected_version = CACHE_SCHEMA_VERSION,
                    "cached root token was rejected because its schema is not current"
                );
                return Ok(None);
            }
            if !super::provenance::matches(github_app, &entry.authority_fingerprint) {
                tracing::debug!(
                    profile = profile_name,
                    account = github_app.account,
                    client_id = github_app.client_id,
                    "cached root token was rejected because its configured authority changed"
                );
                return Ok(None);
            }
            tracing::debug!(
                profile = profile_name,
                github_user = entry.github_user,
                expires_at = %entry.expires_at,
                "root token cache hit"
            );
            Ok(Some(entry))
        }
        other @ (CacheEntry::Derived(_) | CacheEntry::Run(_)) => {
            Err(TokenError::UnexpectedCacheKind {
                profile: profile_name.to_owned(),
                expected: "root",
                actual: other.kind_name(),
            })
        }
    }
}

pub fn persist_root_response<C: RootTokenClient>(
    client: &C,
    profile: &RootProfile,
    profile_name: &str,
    cache_dir: &Path,
    response: IssuedRootToken,
    now: OffsetDateTime,
    epoch: u64,
) -> Result<RootPersistence, TokenError> {
    let IssuedRootToken {
        access_token,
        expires_in,
    } = response;
    let expiry = match validate_root_expiry(expires_in, now) {
        Ok(expiry) => expiry,
        Err(error) => {
            tracing::debug!(profile = profile_name, error = %error, "issued root token had an invalid lifetime");
            return Err(revoke_with_context(client, profile, &access_token, error));
        }
    };
    tracing::debug!(profile = profile_name, expires_at = %expiry, "validated issued root token lifetime");
    let user = match client.get_user(access_token.as_ref()) {
        Ok(user) => user,
        Err(error) => {
            tracing::debug!(profile = profile_name, error = %error, "failed to identify the GitHub user for issued root token");
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
            tracing::debug!(profile = profile_name, error = %error, "failed to persist issued root token");
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
            CacheEntry::Root(entry) => {
                tracing::debug!(profile = profile_name, "persisted issued root token");
                Ok(RootPersistence::Saved(root_status(entry)))
            }
            CacheEntry::Derived(_) | CacheEntry::Run(_) => unreachable!("candidate is root"),
        },
        SaveCacheEntry::Retained(entry) => match *entry {
            CacheEntry::Root(entry) => {
                tracing::debug!(
                    profile = profile_name,
                    "a compatible concurrent root token won the cache race; revoking unused candidate"
                );
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
                    Ok(RootPersistence::Retained(root_status(entry)))
                }
            }
            entry @ (CacheEntry::Derived(_) | CacheEntry::Run(_)) => {
                Err(TokenError::UnexpectedCacheKind {
                    profile: profile_name.to_owned(),
                    expected: "root",
                    actual: entry.kind_name(),
                })
            }
        },
    }
}

fn root_status(entry: RootCacheEntry) -> RootTokenStatus {
    RootTokenStatus {
        github_user: entry.github_user,
        expires_at: entry.expires_at,
    }
}
