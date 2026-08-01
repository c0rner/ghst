use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroizing;

use crate::cache::AccessToken;

/// Response from `POST /login/device/code`
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: Zeroizing<String>,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    #[serde(default = "default_poll_interval")]
    pub interval: u64,
}

// Hand-written Debug to redact device_code
impl fmt::Debug for DeviceCodeResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceCodeResponse")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

const fn default_poll_interval() -> u64 {
    5
}

/// Response from `POST /login/oauth/access_token`
#[derive(PartialEq, Eq, Deserialize)]
pub struct AccessTokenResponse {
    pub access_token: AccessToken,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<Zeroizing<String>>,
    pub refresh_token_expires_in: Option<u64>,
    pub scope: Option<String>,
}

// Hand-written Debug to redact access_token and refresh_token
impl fmt::Debug for AccessTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("refresh_token_expires_in", &self.refresh_token_expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

/// Response from `GET /user`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserResponse {
    pub login: String,
    pub id: u64,
    pub name: Option<String>,
    pub email: Option<String>,
}

/// Request for `POST /applications/{client_id}/token/scoped`
#[derive(Serialize)]
pub struct ScopedTokenRequest<'a> {
    pub access_token: &'a str,
    pub target: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repositories: Option<&'a [String]>,
    pub permissions: &'a BTreeMap<String, String>,
}

// Hand-written Debug to redact access_token
impl fmt::Debug for ScopedTokenRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedTokenRequest")
            .field("access_token", &"[REDACTED]")
            .field("target", &self.target)
            .field("repositories", &self.repositories)
            .field("permissions", &self.permissions)
            .finish()
    }
}

/// Response from `POST /applications/{client_id}/token/scoped`
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedTokenResponse {
    pub token: AccessToken,
    pub expires_at: Option<String>,
    pub permissions: Option<BTreeMap<String, String>>,
    pub repositories: Option<Vec<RepositoryInfo>>,
}

// Hand-written Debug to redact token
impl fmt::Debug for ScopedTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedTokenResponse")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("permissions", &self.permissions)
            .field("repositories", &self.repositories)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryInfo {
    pub id: u64,
    pub name: String,
    pub full_name: String,
}
