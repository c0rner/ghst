use crate::credential::store::DeleteBaseOutcome;
use crate::credential::store::{Inspect, Remove, StoreError};
use crate::credential::stored::StoredBase;
pub mod client;

use std::collections::BTreeMap;
use time::OffsetDateTime;

use super::{
    TokenError, base_cache_key, load_current_base_entry, revoke_with_context,
    validate_scoped_expiry,
};
use crate::credential::{AccessToken, TokenExpiry};
use crate::profile::{AppCredentials, PermissionLevel};
use crate::repository::RepositorySelection;
use crate::token::scoped::client::{IssuedScopedToken, ScopedTokenClient, ScopedTokenRequest};

pub struct PreparedScopedToken<'a> {
    pub profile_name: &'a str,
    pub source_name: &'a str,
    pub app: AppCredentials<'a>,
    pub permissions: &'a BTreeMap<String, PermissionLevel>,
    pub base: StoredBase,
    pub scope: String,
    pub repositories: Option<Vec<String>>,
}

pub struct ValidatedScopedToken {
    pub access_token: AccessToken,
    pub expires_at: TokenExpiry,
    pub received_at: OffsetDateTime,
}

pub fn prepare<'a, S: Inspect + ?Sized>(
    store: &S,
    profile_name: &'a str,
    source_name: &'a str,
    app: AppCredentials<'a>,
    permissions: &'a BTreeMap<String, PermissionLevel>,
    repositories: &RepositorySelection,
) -> Result<PreparedScopedToken<'a>, TokenError> {
    let scope = repositories.canonical();
    let repository_names = repositories.repository_names();
    tracing::debug!(
        profile = profile_name,
        source_profile = source_name,
        account = app.authority.account,
        repo_scope = scope,
        repositories = ?repository_names,
        permissions = ?permissions,
        "resolved scoped token policy"
    );
    let base = load_current_base_entry(store, source_name, &app.authority)?
        .ok_or_else(|| TokenError::NoSourceBaseTokenCached(source_name.to_owned()))?;
    Ok(PreparedScopedToken {
        profile_name,
        source_name,
        app,
        permissions,
        base,
        scope,
        repositories: repository_names,
    })
}

pub fn issue<C: ScopedTokenClient, N: FnMut() -> OffsetDateTime, S: Remove + ?Sized>(
    client: &C,
    prepared: &PreparedScopedToken<'_>,
    store: &S,
    request_time: OffsetDateTime,
    now: &mut N,
) -> Result<ValidatedScopedToken, TokenError> {
    if !prepared.base.expires_at.is_safe_to_handoff_at(request_time) {
        tracing::debug!(
            source_profile = prepared.source_name,
            expires_at = %prepared.base.expires_at,
            "base token is inside the handoff safety margin and cannot mint a scoped token"
        );
        return Err(TokenError::NoSourceBaseTokenCached(
            prepared.source_name.to_owned(),
        ));
    }
    tracing::debug!(
        source_profile = prepared.source_name,
        account = prepared.app.authority.account,
        repo_scope = prepared.scope,
        permissions = ?prepared.permissions,
        "requesting scoped token from GitHub"
    );
    let response = client.create_scoped_token(&ScopedTokenRequest {
        client_id: prepared.app.authority.client_id,
        client_secret: prepared.app.client_secret,
        base_token: prepared.base.access_token.as_ref(),
        target: prepared.app.authority.account,
        repositories: prepared.repositories.as_deref(),
        permissions: prepared.permissions,
    });
    let response = match response {
        Ok(response) => response,
        Err(crate::token::remote::RemoteError::Http {
            status: 401 | 404, ..
        }) => return Err(permanent_rejection_error(prepared, store)?),
        Err(source @ crate::token::remote::RemoteError::Http { status: 403, .. }) => {
            tracing::debug!(
                source_profile = prepared.source_name,
                account = prepared.app.authority.account,
                repo_scope = prepared.scope,
                permissions = ?prepared.permissions,
                "GitHub rejected the scoped token request; requested permissions or repository access likely exceed the GitHub App installation's authority ceiling"
            );
            return Err(TokenError::ScopedTokenForbidden {
                profile: prepared.profile_name.to_owned(),
                source_profile: prepared.source_name.to_owned(),
                source,
            });
        }
        Err(source) => {
            tracing::debug!(source_profile = prepared.source_name, error = %source, "GitHub scoped token request failed");
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
            tracing::debug!(source_profile = prepared.source_name, expires_at = %expires_at, "validated scoped token lifetime");
            Ok(ValidatedScopedToken {
                access_token,
                expires_at,
                received_at,
            })
        }
        Err(error) => {
            tracing::debug!(source_profile = prepared.source_name, error = %error, "issued scoped token had an invalid lifetime");
            Err(revoke_with_context(
                client,
                &prepared.app.as_registration(),
                &access_token,
                error,
            ))
        }
    }
}

fn permanent_rejection_error<S: Remove + ?Sized>(
    prepared: &PreparedScopedToken<'_>,
    store: &S,
) -> Result<TokenError, StoreError> {
    let source_profile = prepared.source_name;
    let generation = prepared.base.generation_fingerprint();
    let outcome = store.delete_base_generation(&base_cache_key(source_profile), &generation)?;
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
            return Ok(TokenError::BaseGenerationChanged(source_profile.to_owned()));
        }
    }
    Ok(TokenError::NoSourceBaseTokenCached(
        source_profile.to_owned(),
    ))
}
