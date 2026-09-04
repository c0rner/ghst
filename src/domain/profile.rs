use std::fmt;

use serde::{Deserialize, Serialize};

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
    fn test_repo_scope_display_formatting() {
        assert_eq!(RepoScope::All.to_string(), "all");
        assert_eq!(RepoScope::Auto.to_string(), "auto");
        assert_eq!(
            RepoScope::Specific("acme/api".into()).to_string(),
            "acme/api"
        );
        assert_eq!(
            RepoScope::Multiple(vec!["acme/api".into(), "acme/web".into()]).to_string(),
            "[acme/api, acme/web]"
        );
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
    fn test_permission_level_display_formatting() {
        assert_eq!(PermissionLevel::Read.to_string(), "read");
        assert_eq!(PermissionLevel::Write.to_string(), "write");
    }
}
