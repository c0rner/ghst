mod acquire;
pub mod cleanup;
mod error;
pub mod revoke;
mod root;
pub mod run;
mod types;
mod validation;

pub use acquire::acquire;
pub use error::TokenError;
pub use root::{
    load_current_root_entry, load_valid_root_entry, load_valid_root_status, persist_root_response,
    root_cache_key,
};
pub use types::{AcquireRequest, AcquiredToken, RootPersistence, RootTokenStatus};
pub use validation::{validate_root_expiry, validate_scoped_expiry};

use crate::config::RootProfile;
use crate::github::RevokeTokenClient;

fn revoke_with_context<C: RevokeTokenClient + ?Sized>(
    client: &C,
    profile: &RootProfile,
    token: &crate::cache::AccessToken,
    context: TokenError,
) -> TokenError {
    let Some(secret) = profile.github_app.client_secret.as_deref() else {
        tracing::warn!(
            "client secret unavailable; unused remote token could not be revoked and may remain active until GitHub invalidates it or it is manually revoked"
        );
        return context;
    };
    match client.delete_token(&profile.github_app.client_id, secret, token.as_ref()) {
        Ok(()) => context,
        Err(source) => TokenError::RevocationFailed {
            context: Box::new(context),
            source,
        },
    }
}

#[cfg(test)]
mod tests;
