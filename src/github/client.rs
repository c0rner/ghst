use crate::github::types::{
    AccessTokenResponse, DeviceCodeResponse, ScopedTokenRequest as ScopedTokenBody,
    ScopedTokenResponse, UserResponse,
};
use crate::token::{
    BaseTokenClient, DeviceAuthorization, DeviceFlowClient, DeviceFlowPoll, GitHubUser,
    IssuedBaseToken, IssuedScopedToken, RemoteError, RevokeTokenClient, ScopedTokenClient,
    ScopedTokenRequest,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::de::DeserializeOwned;
use std::fmt;
use tracing::debug;

const USER_AGENT: &str = concat!("ghst/", env!("CARGO_PKG_VERSION"));
const GITHUB_ACCEPT: &str = "application/vnd.github+json";

pub struct GitHubClient {
    base_url: String,
    api_url: String,
    agent: ureq::Agent,
}

#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for GitHubClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitHubClient")
            .field("base_url", &self.base_url)
            .field("api_url", &self.api_url)
            .field("user_agent", &USER_AGENT)
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
        let config = ureq::Agent::config_builder()
            .user_agent(USER_AGENT)
            .accept(GITHUB_ACCEPT)
            .build();
        Self {
            base_url: base_url.into(),
            api_url: api_url.into(),
            agent: ureq::Agent::new_with_config(config),
        }
    }

    fn request_device_code_response(
        &self,
        client_id: &str,
    ) -> Result<DeviceCodeResponse, RemoteError> {
        let url = format!("{}/login/device/code", self.base_url);
        let body = serde_json::json!({ "client_id": client_id });

        debug!(
            method = "POST",
            endpoint = "/login/device/code",
            client_id,
            "requesting GitHub device code"
        );
        let res = self
            .agent
            .post(&url)
            .header("Accept", "application/json")
            .send_json(&body)
            .map_err(map_ureq_error);
        let res = match res {
            Ok(response) => response,
            Err(error) => {
                debug!(method = "POST", endpoint = "/login/device/code", error = %error, "GitHub device code request failed");
                return Err(error);
            }
        };

        let response: Result<DeviceCodeResponse, RemoteError> = decode_response(res);
        match &response {
            Ok(device) => debug!(
                expires_in_seconds = device.expires_in,
                poll_interval_seconds = device.interval,
                "GitHub device code request succeeded"
            ),
            Err(error) => debug!(error = %error, "failed to decode GitHub device code response"),
        }
        response
    }

    fn poll_access_token_response(
        &self,
        client_id: &str,
        device_code: &str,
    ) -> Result<DeviceFlowPoll, RemoteError> {
        let url = format!("{}/login/oauth/access_token", self.base_url);
        let body = serde_json::json!({
            "client_id": client_id,
            "device_code": device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
        });

        tracing::trace!(
            method = "POST",
            endpoint = "/login/oauth/access_token",
            client_id,
            "polling GitHub device authorization"
        );
        let mut res = self
            .agent
            .post(&url)
            .header("Accept", "application/json")
            .send_json(&body)
            .map_err(map_ureq_error)
            .map_err(|error| {
                debug!(method = "POST", endpoint = "/login/oauth/access_token", error = %error, "GitHub device authorization poll failed");
                error
            })?;

        let value: serde_json::Value =
            res.body_mut()
                .read_json()
                .map_err(map_ureq_error)
                .map_err(|error| {
                    debug!(error = %error, "failed to decode GitHub device authorization response");
                    error
                })?;

        if value.get("error").is_some() {
            return oauth_poll_from_value(&value);
        }

        let response: AccessTokenResponse =
            serde_json::from_value(value).map_err(RemoteError::InvalidResponse)?;
        debug!("GitHub device authorization succeeded");
        Ok(DeviceFlowPoll::Authorized(narrow_base_token(response)))
    }
}

fn decode_response<T: DeserializeOwned>(
    mut response: ureq::http::Response<ureq::Body>,
) -> Result<T, RemoteError> {
    response.body_mut().read_json().map_err(map_ureq_error)
}

fn oauth_poll_from_value(value: &serde_json::Value) -> Result<DeviceFlowPoll, RemoteError> {
    match value.get("error").and_then(serde_json::Value::as_str) {
        Some("authorization_pending") => Ok(DeviceFlowPoll::Pending),
        Some("slow_down") => Ok(DeviceFlowPoll::SlowDown),
        Some("expired_token") => Ok(DeviceFlowPoll::Expired),
        Some("access_denied") => Ok(DeviceFlowPoll::AccessDenied),
        Some(_) => Err(RemoteError::Protocol {
            context: "unexpected OAuth error response",
        }),
        None => Err(RemoteError::Protocol {
            context: "malformed OAuth error response",
        }),
    }
}

impl DeviceFlowClient for GitHubClient {
    fn request_device_code(&self, client_id: &str) -> Result<DeviceAuthorization, RemoteError> {
        self.request_device_code_response(client_id)
            .map(narrow_device_authorization)
    }

    fn poll_access_token(
        &self,
        client_id: &str,
        device_code: &str,
    ) -> Result<DeviceFlowPoll, RemoteError> {
        self.poll_access_token_response(client_id, device_code)
    }
}

impl RevokeTokenClient for GitHubClient {
    fn delete_token(
        &self,
        client_id: &str,
        client_secret: &str,
        access_token: &str,
    ) -> Result<(), RemoteError> {
        let url = format!("{}/applications/{client_id}/token", self.api_url);
        let body = serde_json::json!({ "access_token": access_token });
        let auth = basic_auth_header(client_id, client_secret);
        let body_bytes = serde_json::to_vec(&body).map_err(|_| RemoteError::Protocol {
            context: "failed to encode token revocation request",
        })?;

        let request = ureq::http::Request::builder()
            .method("DELETE")
            .uri(&url)
            .header("Authorization", &auth)
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .map_err(|error| RemoteError::Transport(std::io::Error::other(error)))?;

        debug!(
            method = "DELETE",
            endpoint = "/applications/:client_id/token",
            client_id,
            "revoking GitHub token"
        );
        self.agent.run(request).map_err(map_ureq_error).map_err(|error| {
            debug!(method = "DELETE", endpoint = "/applications/:client_id/token", client_id, error = %error, "GitHub token revocation failed");
            error
        })?;
        debug!(client_id, "GitHub token revocation succeeded");
        Ok(())
    }
}

impl ScopedTokenClient for GitHubClient {
    fn create_scoped_token(
        &self,
        request: &ScopedTokenRequest<'_>,
    ) -> Result<IssuedScopedToken, RemoteError> {
        let url = format!(
            "{}/applications/{}/token/scoped",
            self.api_url, request.client_id
        );
        let body = ScopedTokenBody {
            access_token: request.base_token,
            target: request.target,
            repositories: request.repositories,
            permissions: request.permissions,
        };

        debug!(
            method = "POST",
            endpoint = "/applications/{client_id}/token/scoped",
            client_id = request.client_id,
            request = ?body,
            "creating GitHub scoped token"
        );
        let response = self
            .agent
            .post(&url)
            .header(
                "Authorization",
                &basic_auth_header(request.client_id, request.client_secret),
            )
            .send_json(&body)
            .map_err(map_ureq_error)
            .map_err(|error| {
                debug!(
                    method = "POST",
                    endpoint = "/applications/{client_id}/token/scoped",
                    client_id = request.client_id,
                    error = %error,
                    "GitHub scoped token request failed"
                );
                error
            })?;

        let response = decode_response(response).map(narrow_scoped_token);
        match &response {
            Ok(issued) => {
                debug!(expires_at = ?issued.expires_at, "GitHub scoped token request succeeded");
            }
            Err(error) => debug!(error = %error, "failed to decode GitHub scoped token response"),
        }
        response
    }
}

impl BaseTokenClient for GitHubClient {
    fn get_user(&self, access_token: &str) -> Result<GitHubUser, RemoteError> {
        let url = format!("{}/user", self.api_url);
        debug!(
            method = "GET",
            endpoint = "/user",
            "identifying GitHub user for issued base token"
        );
        let response = self
            .agent
            .get(&url)
            .header("Authorization", &format!("Bearer {access_token}"))
            .call()
            .map_err(map_ureq_error)
            .map_err(|error| {
                debug!(method = "GET", endpoint = "/user", error = %error, "GitHub user request failed");
                error
            })?;

        let response = decode_response(response).map(narrow_user);
        match &response {
            Ok(user) => debug!(github_user = user.login, "identified GitHub user"),
            Err(error) => debug!(error = %error, "failed to decode GitHub user response"),
        }
        response
    }
}

fn narrow_base_token(response: AccessTokenResponse) -> IssuedBaseToken {
    let AccessTokenResponse {
        access_token,
        expires_in,
        refresh_token,
        ..
    } = response;
    drop(refresh_token);
    IssuedBaseToken {
        access_token,
        expires_in,
    }
}

fn narrow_device_authorization(response: DeviceCodeResponse) -> DeviceAuthorization {
    DeviceAuthorization {
        device_code: response.device_code,
        user_code: response.user_code,
        verification_uri: response.verification_uri,
        expires_in: std::time::Duration::from_secs(response.expires_in),
        interval: std::time::Duration::from_secs(response.interval),
    }
}

fn narrow_user(response: UserResponse) -> GitHubUser {
    GitHubUser {
        login: response.login,
    }
}

fn narrow_scoped_token(response: ScopedTokenResponse) -> IssuedScopedToken {
    IssuedScopedToken {
        access_token: response.token,
        expires_at: response.expires_at,
    }
}

fn map_ureq_error(err: ureq::Error) -> RemoteError {
    match err {
        ureq::Error::StatusCode(code) => RemoteError::Http {
            status: code,
            message: format!("HTTP status error {code}"),
        },
        ureq::Error::Json(source) => RemoteError::InvalidResponse(source),
        ureq::Error::Io(source) => RemoteError::Transport(source),
        other => RemoteError::Transport(std::io::Error::other(other.to_string())),
    }
}

fn basic_auth_header(client_id: &str, client_secret: &str) -> String {
    let credentials = format!("{client_id}:{client_secret}");
    format!("Basic {}", STANDARD.encode(credentials.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn configured_agent_has_github_defaults() {
        let client = GitHubClient::new();

        assert!(matches!(
            client.agent.config().user_agent(),
            ureq::config::AutoHeaderValue::Provided(value) if value.as_str() == USER_AGENT
        ));
        assert!(matches!(
            client.agent.config().accept(),
            ureq::config::AutoHeaderValue::Provided(value) if value.as_str() == GITHUB_ACCEPT
        ));
    }

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

        let issued = narrow_base_token(res);
        assert_eq!(
            issued.access_token.as_ref(),
            "ghu_16C7e42F292c6912E7710c838347Ae178B4a"
        );
        assert_eq!(issued.expires_in, Some(28_800));
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

        assert_eq!(
            narrow_user(res),
            GitHubUser {
                login: "octocat".into()
            }
        );
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

        let issued = narrow_scoped_token(res);
        assert_eq!(issued.access_token.as_ref(), "ghu_scoped_1234567890abcdef");
        assert_eq!(issued.expires_at.as_deref(), Some("2026-07-30T18:00:00Z"));
    }

    #[test]
    fn scoped_token_request_serialization_is_exact() {
        use crate::domain::profile::PermissionLevel;

        let repositories = vec!["api".into(), "web".into()];
        let permissions = BTreeMap::from([
            ("contents".into(), PermissionLevel::Read),
            ("pull_requests".into(), PermissionLevel::Write),
        ]);
        let request = ScopedTokenBody {
            access_token: "base-token",
            target: "acme",
            repositories: Some(&repositories),
            permissions: &permissions,
        };
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({
                "access_token": "base-token",
                "target": "acme",
                "repositories": ["api", "web"],
                "permissions": {"contents": "read", "pull_requests": "write"},
            })
        );

        let all_request = ScopedTokenBody {
            access_token: "base-token",
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
    fn known_oauth_errors_map_to_device_flow_states() {
        for (error, expected) in [
            ("authorization_pending", DeviceFlowPoll::Pending),
            ("slow_down", DeviceFlowPoll::SlowDown),
            ("expired_token", DeviceFlowPoll::Expired),
            ("access_denied", DeviceFlowPoll::AccessDenied),
        ] {
            let value = serde_json::json!({ "error": error });
            let actual = oauth_poll_from_value(&value).unwrap();
            assert_eq!(
                std::mem::discriminant(&actual),
                std::mem::discriminant(&expected)
            );
        }
    }

    #[test]
    fn unknown_oauth_error_is_a_redacted_protocol_failure() {
        let value = serde_json::json!({
            "error": "custom_oauth_failure",
            "error_description": "secret response context"
        });

        let error = oauth_poll_from_value(&value).unwrap_err();
        assert!(matches!(error, RemoteError::Protocol { .. }));
        assert_eq!(error.kind(), "protocol");
        assert!(!format!("{error:?} {error}").contains("secret response context"));
        assert!(!format!("{error:?} {error}").contains("custom_oauth_failure"));
    }

    #[test]
    fn malformed_oauth_error_never_falls_through_or_exposes_response() {
        let value = serde_json::json!({
            "error": { "unexpected": "shape" },
            "error_description": 42,
            "access_token": "must-not-appear-in-error"
        });

        let error = oauth_poll_from_value(&value).unwrap_err();
        assert!(matches!(error, RemoteError::Protocol { .. }));
        assert!(!error.to_string().contains("must-not-appear-in-error"));
    }

    #[test]
    fn remote_error_mappings_preserve_classification() {
        let status = map_ureq_error(ureq::Error::StatusCode(404));
        assert!(matches!(status, RemoteError::Http { status: 404, .. }));
        assert_eq!(status.kind(), "http");
        assert!(status.is_not_found());

        let invalid: Result<serde_json::Value, _> = serde_json::from_str("not json");
        let invalid = invalid.unwrap_err();
        let error = map_ureq_error(ureq::Error::Json(invalid));
        assert_eq!(error.kind(), "invalid_response");
        assert!(std::error::Error::source(&error).is_some());

        let error = map_ureq_error(ureq::Error::Io(std::io::Error::other("offline")));
        assert_eq!(error.kind(), "transport");
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn test_basic_auth_header() {
        let header = basic_auth_header("client_id_123", "secret_abc");
        assert_eq!(header, "Basic Y2xpZW50X2lkXzEyMzpzZWNyZXRfYWJj");
    }
}
