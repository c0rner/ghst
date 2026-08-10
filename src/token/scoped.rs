use super::{TokenError, load_current_root_entry, revoke_with_context, validate_scoped_expiry};
use crate::cache::{AccessToken, RootCacheEntry, TokenExpiry};
use crate::config::{Config, DerivedProfile, ProfileConfig, RootProfile};
use crate::github::{ScopedTokenClient, ScopedTokenResponse};
use crate::repository::{RepositoryError, RepositorySelection};
use std::collections::BTreeMap;
use std::path::Path;
use time::OffsetDateTime;

pub(super) struct PreparedScopedToken<'a> {
    pub profile: &'a DerivedProfile,
    pub source: &'a RootProfile,
    pub root: RootCacheEntry,
    pub scope: String,
    pub repositories: Option<Vec<String>>,
    pub permissions: BTreeMap<String, String>,
}

pub(super) struct IssuedScopedToken {
    pub access_token: AccessToken,
    pub expires_at: TokenExpiry,
}

pub(super) fn prepare<'a>(
    config: &'a Config,
    cache_dir: &Path,
    profile_name: &str,
    repositories: &[String],
    resolve_auto: impl FnMut() -> Result<String, RepositoryError>,
) -> Result<PreparedScopedToken<'a>, TokenError> {
    let profile = match config.profiles.get(profile_name) {
        Some(ProfileConfig::Derived(profile)) => profile,
        Some(ProfileConfig::Root(_)) => {
            return Err(TokenError::RunRequiresDerived(profile_name.to_owned()));
        }
        None => return Err(TokenError::ProfileNotFound(profile_name.to_owned())),
    };
    let source = match config.profiles.get(&profile.source) {
        Some(ProfileConfig::Root(source)) => source,
        Some(ProfileConfig::Derived(_)) => {
            return Err(TokenError::SourceProfileNotRoot {
                profile: profile_name.to_owned(),
                source: profile.source.clone(),
            });
        }
        None => return Err(TokenError::ProfileNotFound(profile.source.clone())),
    };
    let selection = RepositorySelection::resolve(
        repositories,
        &profile.repo,
        &source.github_app.account,
        resolve_auto,
    )?;
    let root = load_current_root_entry(cache_dir, &profile.source, &source.github_app)?
        .ok_or_else(|| TokenError::NoSourceTokenCached(profile.source.clone()))?;
    Ok(PreparedScopedToken {
        profile,
        source,
        root,
        scope: selection.canonical(),
        repositories: selection.repository_names(),
        permissions: profile
            .permissions
            .iter()
            .map(|(name, level)| (name.clone(), level.to_string()))
            .collect(),
    })
}

pub(super) fn issue<C: ScopedTokenClient>(
    client: &C,
    prepared: &PreparedScopedToken<'_>,
    now: OffsetDateTime,
) -> Result<IssuedScopedToken, TokenError> {
    if !prepared.root.expires_at.is_usable_at(now) {
        return Err(TokenError::NoSourceTokenCached(
            prepared.profile.source.clone(),
        ));
    }
    let secret = prepared
        .source
        .github_app
        .client_secret
        .as_deref()
        .ok_or_else(|| TokenError::ClientSecretRequired(prepared.profile.source.clone()))?;
    let ScopedTokenResponse {
        token, expires_at, ..
    } = client.create_scoped_token(
        &prepared.source.github_app.client_id,
        secret,
        prepared.root.access_token.as_ref(),
        &prepared.source.github_app.account,
        prepared.repositories.as_deref(),
        &prepared.permissions,
    )?;
    match validate_scoped_expiry(expires_at.as_deref(), now) {
        Ok(expires_at) => Ok(IssuedScopedToken {
            access_token: token,
            expires_at,
        }),
        Err(error) => Err(revoke_with_context(client, prepared.source, &token, error)),
    }
}
