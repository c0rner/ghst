pub mod client;
pub mod error;
pub mod types;

pub use client::GitHubClient;
pub use error::GitHubError;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(res.access_token, "ghu_16C7e42F292c6912E7710c838347Ae178B4a");

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
        assert_eq!(res.id, 583231);
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
        assert_eq!(res.token, "ghu_scoped_1234567890abcdef");

        let debug_str = format!("{res:?}");
        assert!(!debug_str.contains("ghu_scoped_1234567890abcdef"));
        assert!(debug_str.contains("[REDACTED]"));
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
}
