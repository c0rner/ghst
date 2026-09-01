use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroizing;

use crate::cache::AccessToken;
use crate::config::PermissionLevel;

/// Response from `POST /login/device/code`
#[derive(Deserialize)]
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
#[derive(Deserialize)]
pub struct AccessTokenResponse {
    pub access_token: AccessToken,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<Zeroizing<String>>,
}

// Hand-written Debug to redact access_token and refresh_token
impl fmt::Debug for AccessTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Response from `GET /user`
#[derive(Deserialize)]
pub struct UserResponse {
    pub login: String,
}

/// Request for `POST /applications/{client_id}/token/scoped`
#[derive(Serialize)]
pub struct ScopedTokenRequest<'a> {
    pub access_token: &'a str,
    pub target: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repositories: Option<&'a [String]>,
    pub permissions: &'a BTreeMap<String, PermissionLevel>,
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
#[derive(Deserialize)]
pub struct ScopedTokenResponse {
    pub token: AccessToken,
    pub expires_at: Option<String>,
}

// Hand-written Debug to redact token
impl fmt::Debug for ScopedTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedTokenResponse")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}
