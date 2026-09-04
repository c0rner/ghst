use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppAuthority<'a> {
    pub account: &'a str,
    pub client_id: &'a str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AppRegistration<'a> {
    pub authority: AppAuthority<'a>,
    pub client_secret: Option<&'a str>,
}

impl fmt::Debug for AppRegistration<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppRegistration")
            .field("authority", &self.authority)
            .field("client_secret", &self.client_secret.map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AppCredentials<'a> {
    pub authority: AppAuthority<'a>,
    pub client_secret: &'a str,
}

impl fmt::Debug for AppCredentials<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppCredentials")
            .field("authority", &self.authority)
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

impl<'a> AppCredentials<'a> {
    pub const fn as_registration(&self) -> AppRegistration<'a> {
        AppRegistration {
            authority: self.authority,
            client_secret: Some(self.client_secret),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ResolvedTokenProfile<'a> {
    Base {
        name: &'a str,
        app: AppRegistration<'a>,
    },
    Scoped {
        name: &'a str,
        source_name: &'a str,
        app: AppCredentials<'a>,
        repository_scope: &'a RepoScope,
        permissions: &'a BTreeMap<String, PermissionLevel>,
    },
}

impl fmt::Debug for ResolvedTokenProfile<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base { name, app } => f
                .debug_struct("Base")
                .field("name", name)
                .field("app", app)
                .finish(),
            Self::Scoped {
                name,
                source_name,
                app,
                repository_scope,
                permissions,
            } => f
                .debug_struct("Scoped")
                .field("name", name)
                .field("source_name", source_name)
                .field("app", app)
                .field("repository_scope", repository_scope)
                .field("permissions", permissions)
                .finish(),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoScope {
    All,
    #[default]
    Auto,
    #[serde(untagged)]
    Specific(String),
    #[serde(untagged)]
    Multiple(Vec<String>),
}

impl fmt::Display for RepoScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => write!(f, "all"),
            Self::Auto => write!(f, "auto"),
            Self::Specific(repo) => write!(f, "{repo}"),
            Self::Multiple(repositories) => write!(f, "[{}]", repositories.join(", ")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionLevel {
    Read,
    Write,
}

impl fmt::Display for PermissionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct RepoHolder {
        #[serde(default)]
        repo: RepoScope,
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
    struct PermissionHolder {
        permission: PermissionLevel,
    }

    #[test]
    fn test_repo_scope_toml_deserialization_variants() {
        let all: RepoHolder = toml::from_str("repo = \"all\"").unwrap();
        assert_eq!(all.repo, RepoScope::All);

        let auto: RepoHolder = toml::from_str("repo = \"auto\"").unwrap();
        assert_eq!(auto.repo, RepoScope::Auto);

        let default: RepoHolder = toml::from_str("").unwrap();
        assert_eq!(default.repo, RepoScope::Auto);

        let specific: RepoHolder = toml::from_str("repo = \"octo-org/api\"").unwrap();
        assert_eq!(
            specific.repo,
            RepoScope::Specific("octo-org/api".to_string())
        );

        let multiple: RepoHolder =
            toml::from_str("repo = [\"octo-org/api\", \"octo-org/web\"]").unwrap();
        assert_eq!(
            multiple.repo,
            RepoScope::Multiple(vec!["octo-org/api".to_string(), "octo-org/web".to_string(),])
        );

        assert!(toml::from_str::<RepoHolder>("repo = 123").is_err());
        assert!(toml::from_str::<RepoHolder>("repo = false").is_err());
    }

    #[test]
    fn test_permission_level_toml_and_json_serialization_contracts() {
        let read: PermissionHolder = toml::from_str("permission = \"read\"").unwrap();
        assert_eq!(read.permission, PermissionLevel::Read);

        let write: PermissionHolder = toml::from_str("permission = \"write\"").unwrap();
        assert_eq!(write.permission, PermissionLevel::Write);

        assert!(toml::from_str::<PermissionHolder>("permission = \"none\"").is_err());
        assert!(toml::from_str::<PermissionHolder>("permission = \"admin\"").is_err());
        assert!(toml::from_str::<PermissionHolder>("permission = \"Read\"").is_err());

        // Wire contract serialization to JSON matches GitHub API expectation (snake_case lowercase)
        let json = serde_json::to_string(&PermissionLevel::Read).unwrap();
        assert_eq!(json, "\"read\"");

        let json = serde_json::to_string(&PermissionLevel::Write).unwrap();
        assert_eq!(json, "\"write\"");

        let from_json: PermissionLevel = serde_json::from_str("\"read\"").unwrap();
        assert_eq!(from_json, PermissionLevel::Read);
    }

    #[test]
    fn test_app_credentials_and_resolved_profile_debug_redaction() {
        let authority = AppAuthority {
            account: "acme-corp",
            client_id: "Iv1.12345678",
        };
        let secret = "secret_top_secret_value_12345";
        let registration_secret = AppRegistration {
            authority,
            client_secret: Some(secret),
        };
        let reg_debug = format!("{registration_secret:?}");
        assert!(!reg_debug.contains(secret));
        assert!(reg_debug.contains("[REDACTED]"));
        assert!(reg_debug.contains("acme-corp"));
        assert!(reg_debug.contains("Iv1.12345678"));

        let registration_secretless = AppRegistration {
            authority,
            client_secret: None,
        };
        let secretless_debug = format!("{registration_secretless:?}");
        assert!(!secretless_debug.contains("[REDACTED]"));
        assert!(secretless_debug.contains("None"));

        let creds = AppCredentials {
            authority,
            client_secret: secret,
        };
        let creds_debug = format!("{creds:?}");
        assert!(!creds_debug.contains(secret));
        assert!(creds_debug.contains("[REDACTED]"));
        assert!(creds_debug.contains("acme-corp"));
        assert!(creds_debug.contains("Iv1.12345678"));

        let base_profile = ResolvedTokenProfile::Base {
            name: "base-profile",
            app: registration_secret,
        };
        let base_debug = format!("{base_profile:?}");
        assert!(!base_debug.contains(secret));
        assert!(base_debug.contains("[REDACTED]"));
        assert!(base_debug.contains("base-profile"));

        let permissions = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);
        let scoped_profile = ResolvedTokenProfile::Scoped {
            name: "scoped-profile",
            source_name: "base-profile",
            app: creds,
            repository_scope: &RepoScope::Auto,
            permissions: &permissions,
        };
        let scoped_debug = format!("{scoped_profile:?}");
        assert!(!scoped_debug.contains(secret));
        assert!(scoped_debug.contains("[REDACTED]"));
        assert!(scoped_debug.contains("scoped-profile"));
        assert!(scoped_debug.contains("base-profile"));
    }
}
