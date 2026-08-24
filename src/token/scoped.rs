use super::{
    IssuedScopedToken, ScopedTokenClient, ScopedTokenRequest, TokenError, load_current_root_entry,
    revoke_with_context, validate_scoped_expiry,
};
use crate::cache::{AccessToken, RootCacheEntry, TokenExpiry};
use crate::config::{Config, DerivedProfile, ProfileConfig, RootProfile};
use crate::repository::{RepositoryError, RepositorySelection};
use std::collections::BTreeMap;
use std::path::Path;
use time::OffsetDateTime;

pub(super) struct PreparedScopedToken<'a> {
    pub profile_name: &'a str,
    pub profile: &'a DerivedProfile,
    pub source: &'a RootProfile,
    pub root: RootCacheEntry,
    pub scope: String,
    pub repositories: Option<Vec<String>>,
    pub permissions: BTreeMap<String, String>,
}

pub(super) struct ValidatedScopedToken {
    pub access_token: AccessToken,
    pub expires_at: TokenExpiry,
    pub received_at: OffsetDateTime,
}

pub(super) fn prepare<'a>(
    config: &'a Config,
    cache_dir: &Path,
    profile_name: &'a str,
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
    let scope = selection.canonical();
    let repository_names = selection.repository_names();
    tracing::debug!(
        profile = profile_name,
        source_profile = profile.source,
        account = source.github_app.account,
        selection_source = if repositories.is_empty() {
            "profile"
        } else {
            "cli"
        },
        repo_scope = scope,
        repositories = ?repository_names,
        permissions = ?profile.permissions,
        "resolved scoped token policy"
    );
    let root = load_current_root_entry(cache_dir, &profile.source, &source.github_app)?
        .ok_or_else(|| TokenError::NoSourceTokenCached(profile.source.clone()))?;
    Ok(PreparedScopedToken {
        profile_name,
        profile,
        source,
        root,
        scope,
        repositories: repository_names,
        permissions: profile
            .permissions
            .iter()
            .map(|(name, level)| (name.clone(), level.to_string()))
            .collect(),
    })
}

pub(super) fn issue<C: ScopedTokenClient, N: FnMut() -> OffsetDateTime>(
    client: &C,
    prepared: &PreparedScopedToken<'_>,
    request_time: OffsetDateTime,
    now: &mut N,
) -> Result<ValidatedScopedToken, TokenError> {
    if !prepared.root.expires_at.is_safe_to_handoff_at(request_time) {
        tracing::debug!(
            source_profile = prepared.profile.source,
            expires_at = %prepared.root.expires_at,
            "root token is inside the handoff safety margin and cannot mint a scoped token"
        );
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
    tracing::debug!(
        source_profile = prepared.profile.source,
        account = prepared.source.github_app.account,
        repo_scope = prepared.scope,
        permissions = ?prepared.permissions,
        "requesting scoped token from GitHub"
    );
    let response = client.create_scoped_token(&ScopedTokenRequest {
        client_id: &prepared.source.github_app.client_id,
        client_secret: secret,
        root_token: prepared.root.access_token.as_ref(),
        target: &prepared.source.github_app.account,
        repositories: prepared.repositories.as_deref(),
        permissions: &prepared.permissions,
    });
    let response = match response {
        Ok(response) => response,
        Err(source @ crate::github::GitHubError::Http { status: 403, .. }) => {
            tracing::debug!(
                source_profile = prepared.profile.source,
                account = prepared.source.github_app.account,
                repo_scope = prepared.scope,
                permissions = ?prepared.permissions,
                "GitHub rejected the scoped token request; requested permissions or repository access likely exceed the GitHub App installation's authority ceiling"
            );
            return Err(TokenError::ScopedTokenForbidden {
                profile: prepared.profile_name.to_owned(),
                source_profile: prepared.profile.source.clone(),
                source,
            });
        }
        Err(source) => {
            tracing::debug!(source_profile = prepared.profile.source, error = %source, "GitHub scoped token request failed");
            return Err(TokenError::GitHub(source));
        }
    };
    let received_at = now();
    let IssuedScopedToken {
        access_token,
        expires_at,
    } = response;
    match validate_scoped_expiry(expires_at.as_deref(), received_at) {
        Ok(expires_at) => {
            tracing::debug!(source_profile = prepared.profile.source, expires_at = %expires_at, "validated scoped token lifetime");
            Ok(ValidatedScopedToken {
                access_token,
                expires_at,
                received_at,
            })
        }
        Err(error) => {
            tracing::debug!(source_profile = prepared.profile.source, error = %error, "issued scoped token had an invalid lifetime");
            Err(revoke_with_context(
                client,
                prepared.source,
                &access_token,
                error,
            ))
        }
    }
}
