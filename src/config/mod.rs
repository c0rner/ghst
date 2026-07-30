pub mod error;
pub mod types;
pub mod validation;

pub use error::ConfigError;
pub use types::*;

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

impl FromStr for Config {
    type Err = ConfigError;

    fn from_str(content: &str) -> Result<Self, Self::Err> {
        let config: Self = toml::from_str(content).map_err(ConfigError::Parse)?;
        validation::validate_config(&config)?;
        Ok(config)
    }
}

impl Config {
    /// Returns the configuration file path.
    /// Priority: `GHST_CONFIG` environment variable -> `sysdirs::config_dir()/ghst/profiles.toml`.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::ConfigDirNotFound` if `GHST_CONFIG` is unset and user config directory cannot be resolved.
    pub fn default_path() -> Result<PathBuf, ConfigError> {
        if let Some(val) = std::env::var_os("GHST_CONFIG") {
            return Ok(PathBuf::from(val));
        }
        let config_dir = sysdirs::config_dir().ok_or(ConfigError::ConfigDirNotFound)?;
        Ok(config_dir.join("ghst").join("profiles.toml"))
    }

    /// Returns the cache directory path.
    /// Priority: `GHST_CACHE_DIR` environment variable -> `sysdirs::cache_dir()/ghst/`.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::ConfigDirNotFound` if `GHST_CACHE_DIR` is unset and user cache directory cannot be resolved.
    pub fn cache_dir() -> Result<PathBuf, ConfigError> {
        if let Some(val) = std::env::var_os("GHST_CACHE_DIR") {
            return Ok(PathBuf::from(val));
        }
        let cache_dir = sysdirs::cache_dir().ok_or(ConfigError::ConfigDirNotFound)?;
        Ok(cache_dir.join("ghst"))
    }

    /// Loads and validates configuration from the default path.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if directory resolution, file IO, TOML parsing, or validation fails.
    pub fn load() -> Result<Self, ConfigError> {
        let path = Self::default_path()?;
        Self::load_from_path(&path)
    }

    /// Loads and validates configuration from an explicit file path.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if file IO, TOML parsing, or validation fails.
    pub fn load_from_path(path: &Path) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path).map_err(|err| ConfigError::Io {
            path: path.to_path_buf(),
            source: err,
        })?;
        content.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CONFIG: &str = r#"
version = 1
default_profile = "reader"

[profile.developer]
kind = "root"
description = "Full developer privilege ceiling backed by the Dev GitHub App"
github_app.account = "acme-corp"
github_app.client_id = "Iv1.8888888888888888"
github_app.client_secret = "secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

[profile.security-admin]
kind = "root"
description = "Security engineering privilege ceiling with vulnerability access"
github_app.account = "acme-corp"
github_app.client_id = "Iv1.7777777777777777"
github_app.client_secret = "secret_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"
repo = "all"

[profile.reader]
kind = "derived"
description = "Read-only access to repository contents, pull requests, and issues"
source = "developer"
repo = "auto"
permissions = { contents = "read", pull_requests = "read", issues = "read" }

[profile.contributor]
kind = "derived"
description = "Write access to code and pull requests"
source = "developer"
repo = "auto"
permissions = { contents = "write", pull_requests = "write", issues = "write" }

[profile.security-reviewer]
kind = "derived"
description = "Read access focused on vulnerability alerts and security events"
source = "security-admin"
repo = "octo-org/api"
permissions = { contents = "read", security_events = "read", vulnerabilities = "none" }
"#;

    #[test]
    fn test_valid_config_parsing() {
        let config: Config = VALID_CONFIG.parse().unwrap();
        assert_eq!(config.version, 1);
        assert_eq!(config.default_profile.as_deref(), Some("reader"));

        let dev_profile = config.profiles.get("developer").unwrap();
        match dev_profile {
            ProfileConfig::Root(root) => {
                assert_eq!(root.github_app.account, "acme-corp");
                assert_eq!(root.github_app.client_id, "Iv1.8888888888888888");
                assert_eq!(
                    root.github_app.client_secret,
                    "secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                );
            }
            ProfileConfig::Derived(_) => panic!("expected root profile"),
        }

        let reader_profile = config.profiles.get("reader").unwrap();
        match reader_profile {
            ProfileConfig::Derived(derived) => {
                assert_eq!(derived.source, "developer");
                assert_eq!(derived.repo, RepoScope::Auto);
                assert_eq!(
                    derived.permissions.get("contents"),
                    Some(&PermissionLevel::Read)
                );
            }
            ProfileConfig::Root(_) => panic!("expected derived profile"),
        }

        let sec_reviewer = config.profiles.get("security-reviewer").unwrap();
        match sec_reviewer {
            ProfileConfig::Derived(derived) => {
                assert_eq!(derived.source, "security-admin");
                assert_eq!(
                    derived.repo,
                    RepoScope::Specific("octo-org/api".to_string())
                );
                assert_eq!(
                    derived.permissions.get("vulnerabilities"),
                    Some(&PermissionLevel::None)
                );
            }
            ProfileConfig::Root(_) => panic!("expected derived profile"),
        }
    }

    #[test]
    fn test_unsupported_version() {
        let invalid = VALID_CONFIG.replace("version = 1", "version = 2");
        let err: ConfigError = invalid.parse::<Config>().unwrap_err();
        match err {
            ConfigError::UnsupportedVersion(v) => assert_eq!(v, 2),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn test_missing_default_profile() {
        let invalid = VALID_CONFIG.replace(
            "default_profile = \"reader\"",
            "default_profile = \"nonexistent\"",
        );
        let err: ConfigError = invalid.parse::<Config>().unwrap_err();
        match err {
            ConfigError::MissingDefaultProfile(name) => assert_eq!(name, "nonexistent"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn test_derived_chaining_disallowed() {
        let chaining_config = r#"
version = 1
default_profile = "reader"

[profile.developer]
kind = "root"
github_app.account = "acme"
github_app.client_id = "id"
github_app.client_secret = "secret"

[profile.reader]
kind = "derived"
source = "developer"
permissions = { contents = "read" }

[profile.sub_reader]
kind = "derived"
source = "reader"
permissions = { contents = "read" }
"#;
        let err: ConfigError = chaining_config.parse::<Config>().unwrap_err();
        match err {
            ConfigError::DerivedFromNonRoot { profile, source } => {
                assert_eq!(profile, "sub_reader");
                assert_eq!(source, "reader");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn test_secret_redaction_in_debug() {
        let config: Config = VALID_CONFIG.parse().unwrap();
        let debug_str = format!("{config:?}");
        assert!(!debug_str.contains("secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        assert!(!debug_str.contains("secret_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"));
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[test]
    fn test_derived_profile_default_repo() {
        let config_str = r#"
version = 1

[profile.developer]
kind = "root"
github_app.account = "acme"
github_app.client_id = "id"
github_app.client_secret = "secret"

[profile.reader]
kind = "derived"
source = "developer"
permissions = { contents = "read" }
"#;
        let config: Config = config_str.parse().unwrap();
        let reader = config.profiles.get("reader").unwrap();
        match reader {
            ProfileConfig::Derived(derived) => {
                assert_eq!(derived.repo, RepoScope::Auto);
            }
            ProfileConfig::Root(_) => panic!("expected derived profile"),
        }
    }
}
