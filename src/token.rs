mod acquire;
mod base;
mod device_flow;
mod error;
mod ports;
pub mod provenance;
pub mod revoke;
mod scoped;
pub mod store;
mod types;
mod validation;

pub use acquire::acquire;
#[cfg(test)]
pub use base::base_cache_key;
pub use base::{
    load_current_base_entry, load_valid_base_entry, load_valid_base_status, persist_base_response,
};
pub use device_flow::{DeviceFlow, DeviceFlowError};
pub use error::TokenError;
pub use ports::{
    BaseTokenClient, DeviceAuthorization, DeviceFlowClient, DeviceFlowPoll, GitHubUser,
    IssuedBaseToken, IssuedScopedToken, RemoteError, RevokeTokenClient, ScopedTokenClient,
    ScopedTokenRequest,
};
pub use scoped::{FreshScopedTokenRequest, issue_fresh_scoped};
pub use types::{AcquireRequest, AcquiredToken, BasePersistence, BaseTokenStatus};
pub use validation::{validate_base_expiry, validate_scoped_expiry};

use crate::domain::profile::AppRegistration;

pub fn revoke_with_context<C: RevokeTokenClient + ?Sized, E>(
    client: &C,
    app: &AppRegistration<'_>,
    token: &crate::credential::AccessToken,
    context: TokenError<E>,
) -> TokenError<E> {
    let Some(secret) = app.client_secret else {
        tracing::warn!(
            "client secret unavailable; unused remote token could not be revoked and may remain active until GitHub invalidates it or it is manually revoked"
        );
        return context;
    };
    tracing::debug!(
        client_id = app.authority.client_id,
        "revoking unused token after a failed or concurrent operation"
    );
    match client.delete_token(app.authority.client_id, secret, token.as_ref()) {
        Ok(()) => {
            tracing::debug!(client_id = app.authority.client_id, "unused token revoked");
            context
        }
        Err(source) => {
            tracing::debug!(
                client_id = app.authority.client_id,
                error = %source,
                "failed to revoke unused token"
            );
            TokenError::RevocationFailed {
                context: Box::new(context),
                source,
            }
        }
    }
}

#[cfg(test)]
mod tests;
