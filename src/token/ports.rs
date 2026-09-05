use crate::domain::credential::AccessToken;
use crate::domain::profile::PermissionLevel;
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum RemoteError {
    Transport(std::io::Error),
    InvalidResponse(serde_json::Error),
    Http { status: u16, message: String },
    Protocol { context: &'static str },
}

impl RemoteError {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Transport(_) => "transport",
            Self::InvalidResponse(_) => "invalid_response",
            Self::Http { .. } => "http",
            Self::Protocol { .. } => "protocol",
        }
    }

    pub const fn is_not_found(&self) -> bool {
        matches!(self, Self::Http { status: 404, .. })
    }
}

impl fmt::Display for RemoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(source) => write!(formatter, "transport error: {source}"),
            Self::InvalidResponse(source) => write!(formatter, "invalid response: {source}"),
            Self::Http { status, message } => {
                write!(formatter, "HTTP status {status}: {message}")
            }
            Self::Protocol { context } => write!(formatter, "protocol failure: {context}"),
        }
    }
}

impl std::error::Error for RemoteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(source) => Some(source),
            Self::InvalidResponse(source) => Some(source),
            Self::Http { .. } | Self::Protocol { .. } => None,
        }
    }
}

pub trait RevokeTokenClient {
    fn delete_token(
        &self,
        client_id: &str,
        client_secret: &str,
        access_token: &str,
    ) -> Result<(), RemoteError>;
}

pub trait BaseTokenClient: RevokeTokenClient {
    fn get_user(&self, access_token: &str) -> Result<GitHubUser, RemoteError>;
}

pub trait ScopedTokenClient: RevokeTokenClient {
    fn create_scoped_token(
        &self,
        request: &ScopedTokenRequest<'_>,
    ) -> Result<IssuedScopedToken, RemoteError>;
}

pub trait DeviceFlowClient {
    fn request_device_code(&self, client_id: &str) -> Result<DeviceAuthorization, RemoteError>;

    fn poll_access_token(
        &self,
        client_id: &str,
        device_code: &str,
    ) -> Result<DeviceFlowPoll, RemoteError>;
}

pub struct DeviceAuthorization {
    pub device_code: Zeroizing<String>,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: Duration,
    pub interval: Duration,
}

impl fmt::Debug for DeviceAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceAuthorization")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

#[derive(Debug)]
pub enum DeviceFlowPoll {
    Pending,
    SlowDown,
    Authorized(IssuedBaseToken),
    Expired,
    AccessDenied,
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
    pub permissions: &'a BTreeMap<String, PermissionLevel>,
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
        let permissions = BTreeMap::from([("contents".into(), PermissionLevel::Read)]);
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
