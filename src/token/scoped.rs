use super::{
    IssuedScopedToken, ScopedTokenClient, ScopedTokenRequest, TokenError, base_cache_key,
    load_current_base_entry, revoke_with_context, validate_scoped_expiry,
};
use crate::cache::{
    AccessToken, BaseCacheEntry, CacheError, DeleteBaseOutcome, TokenExpiry,
    delete_base_if_generation,
};
use crate::config::{AppProfile, Config, ProfileConfig, ScopedProfile};
use crate::repository::{RepositoryError, RepositorySelection};
use std::collections::BTreeMap;
use std::path::Path;
use time::OffsetDateTime;

pub(super) struct PreparedScopedToken<'a> {
    pub profile_name: &'a str,
    pub profile: &'a ScopedProfile,
    pub source: &'a AppProfile,
    pub base: BaseCacheEntry,
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
        Some(ProfileConfig::Scoped(profile)) => profile,
        Some(ProfileConfig::App(_)) => {
            return Err(TokenError::RunRequiresScoped(profile_name.to_owned()));
        }
        None => return Err(TokenError::ProfileNotFound(profile_name.to_owned())),
    };
    let source = match config.profiles.get(&profile.source) {
        Some(ProfileConfig::App(source)) => source,
        Some(ProfileConfig::Scoped(_)) => {
            return Err(TokenError::SourceProfileNotApp {
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
    let base = load_current_base_entry(cache_dir, &profile.source, &source.github_app)?
        .ok_or_else(|| TokenError::NoSourceBaseTokenCached(profile.source.clone()))?;
    Ok(PreparedScopedToken {
        profile_name,
        profile,
        source,
        base,
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
    cache_dir: &Path,
    request_time: OffsetDateTime,
    now: &mut N,
) -> Result<ValidatedScopedToken, TokenError> {
    if !prepared.base.expires_at.is_safe_to_handoff_at(request_time) {
        tracing::debug!(
            source_profile = prepared.profile.source,
            expires_at = %prepared.base.expires_at,
            "base token is inside the handoff safety margin and cannot mint a scoped token"
        );
        return Err(TokenError::NoSourceBaseTokenCached(
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
        base_token: prepared.base.access_token.as_ref(),
        target: &prepared.source.github_app.account,
        repositories: prepared.repositories.as_deref(),
        permissions: &prepared.permissions,
    });
    let response = match response {
        Ok(response) => response,
        Err(crate::github::GitHubError::Http {
            status: 401 | 404, ..
        }) => return Err(permanent_rejection_error(prepared, cache_dir)?),
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

fn permanent_rejection_error(
    prepared: &PreparedScopedToken<'_>,
    cache_dir: &Path,
) -> Result<TokenError, CacheError> {
    let source_profile = &prepared.profile.source;
    let generation = prepared.base.generation_fingerprint();
    let outcome =
        delete_base_if_generation(cache_dir, &base_cache_key(source_profile), &generation)?;
    match outcome {
        DeleteBaseOutcome::Deleted => tracing::warn!(
            source_profile,
            "evicted cached base token after GitHub permanently rejected it"
        ),
        DeleteBaseOutcome::Missing => tracing::debug!(
            source_profile,
            "rejected base token was already removed while minting"
        ),
        DeleteBaseOutcome::Changed => {
            tracing::debug!(
                source_profile,
                "rejected base token was replaced while minting"
            );
            return Ok(TokenError::BaseGenerationChanged(source_profile.clone()));
        }
    }
    Ok(TokenError::NoSourceBaseTokenCached(source_profile.clone()))
}
