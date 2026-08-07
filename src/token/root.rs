use super::{
    RootPersistence, RootTokenStatus, TokenError, revoke_with_context, validate_root_expiry,
};
use crate::cache::{
    CACHE_SCHEMA_VERSION, CacheEntry, RootCacheEntry, SaveCacheEntry, authority_fingerprint,
    compute_cache_key, format_rfc3339, load_cache_entry, save_cache_candidate,
};
use crate::config::{GitHubAppConfig, RootProfile};
use crate::github::{AccessTokenResponse, RootTokenClient};
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
    Ok(
        load_current_root_entry(cache_dir, profile_name, &profile.github_app)?
            .filter(|entry| entry.expires_at.is_usable_at(now)),
    )
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
            CacheEntry::Root(entry) => Ok(RootPersistence::Saved(root_status(entry))),
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
                    Ok(RootPersistence::Retained(root_status(entry)))
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

fn root_status(entry: RootCacheEntry) -> RootTokenStatus {
    RootTokenStatus {
        github_user: entry.github_user,
        expires_at: entry.expires_at,
    }
}
