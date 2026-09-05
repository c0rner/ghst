use super::remote::{RemoteError, RevokeTokenClient};
use crate::domain::credential::AccessToken;
use std::fmt;

pub trait BaseTokenClient: RevokeTokenClient {
    fn get_user(&self, access_token: &str) -> Result<GitHubUser, RemoteError>;
}

pub struct IssuedBaseToken {
    pub access_token: AccessToken,
    pub expires_in: Option<u64>,
}

impl fmt::Debug for IssuedBaseToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedBaseToken")
            .field("access_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubUser {
    pub login: String,
}
