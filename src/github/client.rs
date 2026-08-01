use crate::github::error::GitHubError;
use crate::github::types::{
    AccessTokenResponse, DeviceCodeResponse, OAuthErrorResponse, ScopedTokenRequest,
    ScopedTokenResponse, UserResponse,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::collections::BTreeMap;
use std::fmt;
use tracing::debug;

pub struct GitHubClient {
    base_url: String,
    api_url: String,
    user_agent: String,
}

pub trait ScopedTokenClient {
    fn create_scoped_token(
        &self,
        client_id: &str,
        client_secret: &str,
        root_token: &str,
        target: &str,
        repositories: Option<&[String]>,
        permissions: &BTreeMap<String, String>,
    ) -> Result<ScopedTokenResponse, GitHubError>;

    fn delete_token(
        &self,
        client_id: &str,
        client_secret: &str,
        access_token: &str,
    ) -> Result<(), GitHubError>;
}

pub trait RootTokenClient {
    fn get_user(&self, access_token: &str) -> Result<UserResponse, GitHubError>;

    fn delete_token(
        &self,
        client_id: &str,
        client_secret: &str,
        access_token: &str,
    ) -> Result<(), GitHubError>;
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

        if value.get("error").is_some() {
            if let Ok(oauth_err) = serde_json::from_value::<OAuthErrorResponse>(value.clone()) {
                return match oauth_err.error.as_str() {
                    "authorization_pending" => Err(GitHubError::OAuthPending),
                    "slow_down" => Err(GitHubError::OAuthSlowDown),
                    "expired_token" => Err(GitHubError::OAuthExpired),
                    "access_denied" => Err(GitHubError::OAuthAccessDenied),
                    _ => Err(GitHubError::OAuthError {
                        error: oauth_err.error,
                        description: oauth_err.error_description,
                    }),
                };
            }
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
        target: &str,
        repositories: Option<&[String]>,
        permissions: &BTreeMap<String, String>,
    ) -> Result<ScopedTokenResponse, GitHubError> {
        let url = format!("{}/applications/{client_id}/token/scoped", self.api_url);
        let req_body = ScopedTokenRequest {
            access_token: root_token,
            target,
            repositories,
            permissions,
        };

        debug!("Creating scoped token with request body: {:?}", req_body);
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

impl ScopedTokenClient for GitHubClient {
    fn create_scoped_token(
        &self,
        client_id: &str,
        client_secret: &str,
        root_token: &str,
        target: &str,
        repositories: Option<&[String]>,
        permissions: &BTreeMap<String, String>,
    ) -> Result<ScopedTokenResponse, GitHubError> {
        Self::create_scoped_token(
            self,
            client_id,
            client_secret,
            root_token,
            target,
            repositories,
            permissions,
        )
    }

    fn delete_token(
        &self,
        client_id: &str,
        client_secret: &str,
        access_token: &str,
    ) -> Result<(), GitHubError> {
        Self::delete_token(self, client_id, client_secret, access_token)
    }
}

impl RootTokenClient for GitHubClient {
    fn get_user(&self, access_token: &str) -> Result<UserResponse, GitHubError> {
        Self::get_user(self, access_token)
    }

    fn delete_token(
        &self,
        client_id: &str,
        client_secret: &str,
        access_token: &str,
    ) -> Result<(), GitHubError> {
        Self::delete_token(self, client_id, client_secret, access_token)
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
    format!("Basic {}", STANDARD.encode(credentials.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::types::OAuthErrorResponse;

    #[test]
    fn test_device_code_response_deserialization() {
        let json_data = r#"{
            "device_code": "3584d83530557fdd1f46af8289938c8ef7f0535a",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 900,
            "interval": 5
        }"#;

        let res: DeviceCodeResponse = serde_json::from_str(json_data).unwrap();
        assert_eq!(res.user_code, "WDJB-MJHT");
        assert_eq!(res.expires_in, 900);
        assert_eq!(res.interval, 5);

        let debug_str = format!("{res:?}");
        assert!(!debug_str.contains("3584d83530557fdd1f46af8289938c8ef7f0535a"));
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[test]
    fn test_access_token_response_deserialization_and_debug_redaction() {
        let json_data = r#"{
            "access_token": "ghu_16C7e42F292c6912E7710c838347Ae178B4a",
            "token_type": "bearer",
            "expires_in": 28800,
            "refresh_token": "ghr_1B4a2e4F292c6912E7710c838347Ae178B4b",
            "refresh_token_expires_in": 15811200,
            "scope": ""
        }"#;

        let res: AccessTokenResponse = serde_json::from_str(json_data).unwrap();
        assert!(res.refresh_token.is_some());
        assert_eq!(
            res.access_token.as_ref(),
            "ghu_16C7e42F292c6912E7710c838347Ae178B4a"
        );

        let debug_str = format!("{res:?}");
        assert!(!debug_str.contains("ghu_16C7e42F292c6912E7710c838347Ae178B4a"));
        assert!(!debug_str.contains("ghr_1B4a2e4F292c6912E7710c838347Ae178B4b"));
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[test]
    fn test_user_response_deserialization() {
        let json_data = r#"{
            "login": "octocat",
            "id": 583231,
            "name": "The Octocat",
            "email": "octocat@github.com"
        }"#;

        let res: UserResponse = serde_json::from_str(json_data).unwrap();
        assert_eq!(res.login, "octocat");
        assert_eq!(res.id, 583_231);
        assert_eq!(res.name.as_deref(), Some("The Octocat"));
    }

    #[test]
    fn test_scoped_token_response_deserialization_and_debug_redaction() {
        let json_data = r#"{
            "token": "ghu_scoped_1234567890abcdef",
            "expires_at": "2026-07-30T18:00:00Z",
            "permissions": {
                "contents": "read",
                "issues": "read"
            },
            "repositories": [
                {
                    "id": 1296269,
                    "name": "Hello-World",
                    "full_name": "octocat/Hello-World"
                }
            ]
        }"#;

        let res: ScopedTokenResponse = serde_json::from_str(json_data).unwrap();
        assert_eq!(res.token.as_ref(), "ghu_scoped_1234567890abcdef");

        let debug_str = format!("{res:?}");
        assert!(!debug_str.contains("ghu_scoped_1234567890abcdef"));
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[test]
    fn scoped_token_request_serialization_is_exact() {
        let repositories = vec!["api".into(), "web".into()];
        let permissions = BTreeMap::from([
            ("contents".into(), "read".into()),
            ("pull_requests".into(), "write".into()),
        ]);
        let request = ScopedTokenRequest {
            access_token: "root-token",
            target: "acme",
            repositories: Some(&repositories),
            permissions: &permissions,
        };
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({
                "access_token": "root-token",
                "target": "acme",
                "repositories": ["api", "web"],
                "permissions": {"contents": "read", "pull_requests": "write"},
            })
        );

        let all_request = ScopedTokenRequest {
            access_token: "root-token",
            target: "acme",
            repositories: None,
            permissions: &permissions,
        };
        assert!(
            serde_json::to_value(all_request)
                .unwrap()
                .get("repositories")
                .is_none()
        );
    }

    #[test]
    fn test_oauth_error_response_deserialization() {
        let json_data = r#"{
            "error": "authorization_pending",
            "error_description": "The authorization request is still pending.",
            "error_uri": "https://docs.github.com/apps/building-oauth-apps/authorizing-oauth-apps/"
        }"#;

        let res: OAuthErrorResponse = serde_json::from_str(json_data).unwrap();
        assert_eq!(res.error, "authorization_pending");
    }

    #[test]
    fn test_basic_auth_header() {
        let header = basic_auth_header("client_id_123", "secret_abc");
        assert_eq!(header, "Basic Y2xpZW50X2lkXzEyMzpzZWNyZXRfYWJj");
    }
}
