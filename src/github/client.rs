use crate::github::error::GitHubError;
use crate::github::types::{
    AccessTokenResponse, DeviceCodeResponse, ScopedTokenRequest, ScopedTokenResponse, UserResponse,
};
use std::collections::BTreeMap;
use std::fmt;

pub struct GitHubClient {
    base_url: String,
    api_url: String,
    user_agent: String,
}

impl fmt::Debug for GitHubClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitHubClient")
            .field("base_url", &self.base_url)
            .field("api_url", &self.api_url)
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

impl Default for GitHubClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GitHubClient {
    /// Creates a new `GitHubClient` targeting standard GitHub endpoints.
    pub fn new() -> Self {
        Self::with_urls("https://github.com", "https://api.github.com")
    }

    /// Creates a `GitHubClient` with custom base and API URLs (useful for testing or GHES).
    pub fn with_urls(base_url: impl Into<String>, api_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_url: api_url.into(),
            user_agent: format!("ghst/{}", env!("CARGO_PKG_VERSION")),
        }
    }

    /// 1. Request device code (`POST /login/device/code`).
    ///
    /// # Errors
    ///
    /// Returns `GitHubError` if transport, HTTP status, or JSON parsing fails.
    pub fn request_device_code(&self, client_id: &str) -> Result<DeviceCodeResponse, GitHubError> {
        let url = format!("{}/login/device/code", self.base_url);
        let body = serde_json::json!({ "client_id": client_id });

        let mut res = ureq::post(&url)
            .header("Accept", "application/json")
            .header("User-Agent", &self.user_agent)
            .send_json(&body)
            .map_err(map_ureq_error)?;

        res.body_mut().read_json().map_err(map_ureq_error)
    }

    /// 2. Poll for token (`POST /login/oauth/access_token`).
    ///
    /// # Errors
    ///
    /// Returns `GitHubError` indicating success (`AccessTokenResponse`) or OAuth pending/error states.
    pub fn poll_access_token(
        &self,
        client_id: &str,
        device_code: &str,
    ) -> Result<AccessTokenResponse, GitHubError> {
        let url = format!("{}/login/oauth/access_token", self.base_url);
        let body = serde_json::json!({
            "client_id": client_id,
            "device_code": device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
        });

        let mut res = ureq::post(&url)
            .header("Accept", "application/json")
            .header("User-Agent", &self.user_agent)
            .send_json(&body)
            .map_err(map_ureq_error)?;

        let value: serde_json::Value = res.body_mut().read_json().map_err(map_ureq_error)?;

        if let Some(err_code) = value.get("error").and_then(|v| v.as_str()) {
            return match err_code {
                "authorization_pending" => Err(GitHubError::OAuthPending),
                "slow_down" => Err(GitHubError::OAuthSlowDown),
                "expired_token" => Err(GitHubError::OAuthExpired),
                "access_denied" => Err(GitHubError::OAuthAccessDenied),
                _ => Err(GitHubError::OAuthError {
                    error: err_code.to_string(),
                    description: value
                        .get("error_description")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string),
                }),
            };
        }

        serde_json::from_value(value).map_err(GitHubError::Json)
    }

    /// 3. Get authenticated user (`GET /user`).
    ///
    /// # Errors
    ///
    /// Returns `GitHubError` if request or deserialization fails.
    pub fn get_user(&self, access_token: &str) -> Result<UserResponse, GitHubError> {
        let url = format!("{}/user", self.api_url);

        let mut res = ureq::get(&url)
            .header("Authorization", &format!("Bearer {access_token}"))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", &self.user_agent)
            .call()
            .map_err(map_ureq_error)?;

        res.body_mut().read_json().map_err(map_ureq_error)
    }

    /// 4. Create scoped access token (`POST /applications/{client_id}/token/scoped`).
    ///
    /// # Errors
    ///
    /// Returns `GitHubError` if token scoping request fails.
    pub fn create_scoped_token(
        &self,
        client_id: &str,
        client_secret: &str,
        root_token: &str,
        target: Option<&str>,
        repositories: Option<&[String]>,
        permissions: Option<&BTreeMap<String, String>>,
    ) -> Result<ScopedTokenResponse, GitHubError> {
        let url = format!("{}/applications/{client_id}/token/scoped", self.api_url);
        let req_body = ScopedTokenRequest {
            access_token: root_token,
            target,
            repositories,
            permissions,
        };

        let auth = basic_auth_header(client_id, client_secret);

        let mut res = ureq::post(&url)
            .header("Authorization", &auth)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", &self.user_agent)
            .send_json(&req_body)
            .map_err(map_ureq_error)?;

        res.body_mut().read_json().map_err(map_ureq_error)
    }

    /// 5. Delete an app token (`DELETE /applications/{client_id}/token`).
    ///
    /// # Errors
    ///
    /// Returns `GitHubError` if token revocation fails.
    pub fn delete_token(
        &self,
        client_id: &str,
        client_secret: &str,
        access_token: &str,
    ) -> Result<(), GitHubError> {
        let url = format!("{}/applications/{client_id}/token", self.api_url);
        let body = serde_json::json!({ "access_token": access_token });
        let auth = basic_auth_header(client_id, client_secret);
        let body_bytes = serde_json::to_vec(&body).map_err(GitHubError::Json)?;

        let req = ureq::http::Request::builder()
            .method("DELETE")
            .uri(&url)
            .header("Authorization", &auth)
            .header("Accept", "application/vnd.github+json")
            .header("Content-Type", "application/json")
            .header("User-Agent", &self.user_agent)
            .body(body_bytes)
            .map_err(|e| GitHubError::Io(std::io::Error::other(e)))?;

        let agent = ureq::Agent::new_with_defaults();
        let _res = agent.run(req).map_err(map_ureq_error)?;

        Ok(())
    }
}

fn map_ureq_error(err: ureq::Error) -> GitHubError {
    match err {
        ureq::Error::StatusCode(code) => GitHubError::Http {
            status: code,
            message: format!("HTTP status error {code}"),
        },
        other => GitHubError::Io(std::io::Error::other(other.to_string())),
    }
}

fn basic_auth_header(client_id: &str, client_secret: &str) -> String {
    let credentials = format!("{client_id}:{client_secret}");
    format!("Basic {}", base64_encode(credentials.as_bytes()))
}

fn base64_encode(input: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        out.push(CHARSET[(b0 >> 2) as usize] as char);
        out.push(CHARSET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);

        if chunk.len() > 1 {
            out.push(CHARSET[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(CHARSET[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}
