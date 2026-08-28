mod acquire;
mod base;
pub mod cleanup;
mod error;
mod ports;
mod provenance;
pub mod revoke;
pub mod run;
mod scoped;
mod types;
mod validation;

pub use acquire::acquire;
pub use base::{
    base_cache_key, load_current_base_entry, load_valid_base_entry, load_valid_base_status,
    persist_base_response,
};
pub use error::TokenError;
pub use ports::{
    BaseTokenClient, GitHubUser, IssuedBaseToken, IssuedScopedToken, RevokeTokenClient,
    ScopedTokenClient, ScopedTokenRequest,
};
pub use types::{AcquireRequest, AcquiredToken, BasePersistence, BaseTokenStatus};
pub use validation::{validate_base_expiry, validate_scoped_expiry};

use crate::config::BaseProfile;
fn revoke_with_context<C: RevokeTokenClient + ?Sized>(
    client: &C,
    profile: &BaseProfile,
    token: &crate::cache::AccessToken,
    context: TokenError,
) -> TokenError {
    let Some(secret) = profile.github_app.client_secret.as_deref() else {
        tracing::warn!(
            "client secret unavailable; unused remote token could not be revoked and may remain active until GitHub invalidates it or it is manually revoked"
        );
        return context;
    };
    tracing::debug!(
        client_id = profile.github_app.client_id,
        "revoking unused token after a failed or concurrent operation"
    );
    match client.delete_token(&profile.github_app.client_id, secret, token.as_ref()) {
        Ok(()) => {
            tracing::debug!(
                client_id = profile.github_app.client_id,
                "unused token revoked"
            );
            context
        }
        Err(source) => {
            tracing::debug!(client_id = profile.github_app.client_id, error = %source, "failed to revoke unused token");
            TokenError::RevocationFailed {
                context: Box::new(context),
                source,
            }
        }
    }
}

#[cfg(test)]
mod tests;
