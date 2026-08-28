use crate::cache::AccessToken;
use crate::github::GitHubError;
use std::collections::BTreeMap;
use std::fmt;

pub trait RevokeTokenClient {
    fn delete_token(
        &self,
        client_id: &str,
        client_secret: &str,
        access_token: &str,
    ) -> Result<(), GitHubError>;
}

pub trait BaseTokenClient: RevokeTokenClient {
    fn get_user(&self, access_token: &str) -> Result<GitHubUser, GitHubError>;
}

pub trait ScopedTokenClient: RevokeTokenClient {
    fn create_scoped_token(
        &self,
        request: &ScopedTokenRequest<'_>,
    ) -> Result<IssuedScopedToken, GitHubError>;
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

pub struct ScopedTokenRequest<'a> {
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub base_token: &'a str,
    pub target: &'a str,
    pub repositories: Option<&'a [String]>,
    pub permissions: &'a BTreeMap<String, String>,
}

impl fmt::Debug for ScopedTokenRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedTokenRequest")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("base_token", &"[REDACTED]")
            .field("target", &self.target)
            .field("repositories", &self.repositories)
            .field("permissions", &self.permissions)
            .finish()
    }
}

pub struct IssuedScopedToken {
    pub access_token: AccessToken,
    pub expires_at: Option<String>,
}

impl fmt::Debug for IssuedScopedToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedScopedToken")
            .field("access_token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_request_debug_redacts_credentials() {
        let permissions = BTreeMap::from([("contents".into(), "read".into())]);
        let request = ScopedTokenRequest {
            client_id: "client-id",
            client_secret: "secret-marker",
            base_token: "base-token-marker",
            target: "acme",
            repositories: None,
            permissions: &permissions,
        };

        let output = format!("{request:?}");
        assert!(!output.contains("secret-marker"));
        assert!(!output.contains("base-token-marker"));
        assert!(output.contains("[REDACTED]"));
    }
}
