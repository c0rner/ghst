mod error;
mod types;
mod validation;

pub use error::ConfigError;
#[cfg(test)]
use types::PermissionLevel;
pub use types::{Config, DerivedProfile, GitHubAppConfig, ProfileConfig, RepoScope, RootProfile};

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;

impl FromStr for Config {
    type Err = ConfigError;

    fn from_str(content: &str) -> Result<Self, Self::Err> {
        let config: Self = toml::from_str(content).map_err(|mut source| {
            source.set_input(None);
            ConfigError::Parse(source)
        })?;
        validation::validate_config(&config)?;
        Ok(config)
    }
}

/// Loads and validates configuration from an explicit path or the default location.
///
/// # Errors
///
/// Returns `ConfigError` if path resolution, file IO, TOML parsing, or validation fails.
pub fn load(path: Option<&Path>) -> Result<Config, ConfigError> {
    let path = match path {
        Some(path) => path.to_path_buf(),
        None => config_path()?,
    };
    let mut file = open_config_file(&path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|source| ConfigError::Io {
            path: path.clone(),
            source,
        })?;
    content.parse()
}

#[cfg(unix)]
fn open_config_file(path: &Path) -> Result<File, ConfigError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let flags = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).map_err(|_| {
        ConfigError::InsecurePath {
            path: path.to_path_buf(),
            reason: "required filesystem open flags are not supported",
        }
    })?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata = file.metadata().map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let reason = if !metadata.is_file() {
        Some("expected a regular file")
    } else if metadata.nlink() != 1 {
        Some("hard links are not permitted")
    } else if metadata.uid() != rustix::process::geteuid().as_raw() {
        Some("not owned by the effective user")
    } else if metadata.permissions().mode() & 0o7777 != 0o600 {
        Some("unexpected permissions")
    } else {
        None
    };
    reason.map_or_else(
        || Ok(file),
        |reason| {
            Err(ConfigError::InsecurePath {
                path: path.to_path_buf(),
                reason,
            })
        },
    )
}

#[cfg(not(unix))]
fn open_config_file(path: &Path) -> Result<File, ConfigError> {
    Err(ConfigError::InsecurePath {
        path: path.to_path_buf(),
        reason: "secure configuration loading is not supported on this platform",
    })
}

fn config_path() -> Result<PathBuf, ConfigError> {
    if let Some(value) = std::env::var_os("GHST_CONFIG") {
        return Ok(PathBuf::from(value));
    }
    let config_dir = sysdirs::config_dir().ok_or(ConfigError::ConfigDirNotFound)?;
    Ok(config_dir.join("ghst").join("profiles.toml"))
}

/// Returns the cache directory path.
///
/// # Errors
///
/// Returns `ConfigError::CacheDirNotFound` if `GHST_CACHE_DIR` is unset and the user cache directory cannot be resolved.
pub fn cache_dir() -> Result<PathBuf, ConfigError> {
    if let Some(value) = std::env::var_os("GHST_CACHE_DIR") {
        return Ok(PathBuf::from(value));
    }
    let cache_dir = sysdirs::cache_dir().ok_or(ConfigError::CacheDirNotFound)?;
    Ok(cache_dir.join("ghst"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CONFIG: &str = r#"
version = 1
default_profile = "reader"

[profile.developer]
description = "Full developer privilege ceiling backed by the Dev GitHub App"
github_app.account = "acme-corp"
github_app.client_id = "Iv1.8888888888888888"
github_app.client_secret = "secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

[profile.security-admin]
description = "Security engineering privilege ceiling with vulnerability access"
github_app.account = "acme-corp"
github_app.client_id = "Iv1.7777777777777777"
github_app.client_secret = "secret_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"

[profile.reader]
description = "Read-only access to repository contents, pull requests, and issues"
source = "developer"
repo = "auto"
permissions = { contents = "read", pull_requests = "read", issues = "read" }

[profile.contributor]
description = "Write access to code and pull requests"
source = "developer"
repo = "auto"
permissions = { contents = "write", pull_requests = "write", issues = "write" }

[profile.security-reviewer]
description = "Read access focused on vulnerability alerts and security events"
source = "security-admin"
repo = "octo-org/api"
permissions = { contents = "read", security_events = "read", vulnerability_alerts = "read" }
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
                    root.github_app.client_secret.as_deref(),
                    Some("secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
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
                    derived.permissions.get("vulnerability_alerts"),
                    Some(&PermissionLevel::Read)
                );
            }
            ProfileConfig::Root(_) => panic!("expected derived profile"),
        }
    }

    #[test]
    fn test_none_permission_level_is_rejected() {
        let invalid = VALID_CONFIG.replace(
            "vulnerability_alerts = \"read\"",
            "vulnerability_alerts = \"none\"",
        );
        let err: ConfigError = invalid.parse::<Config>().unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
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
github_app.account = "acme"
github_app.client_id = "id"
github_app.client_secret = "secret"

[profile.reader]
source = "developer"
permissions = { contents = "read" }

[profile.sub_reader]
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
    fn standalone_secretless_root_can_be_default() {
        let config: Config = r#"
version = 1
default_profile = "developer"

[profile.developer]
github_app.account = "acme"
github_app.client_id = "id"
"#
        .parse()
        .unwrap();
        let ProfileConfig::Root(root) = config.profiles.get("developer").unwrap() else {
            panic!("expected root profile");
        };
        assert_eq!(root.github_app.client_secret, None);
        assert!(format!("{config:?}").contains("client_secret: None"));
    }

    #[test]
    fn empty_configured_secret_is_invalid() {
        let invalid = VALID_CONFIG.replace("secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "   ");
        assert!(matches!(
            invalid.parse::<Config>(),
            Err(ConfigError::InvalidRootProfile { .. })
        ));
    }

    #[test]
    fn derived_profile_cannot_reference_secretless_root() {
        let invalid = VALID_CONFIG.replace(
            "github_app.client_secret = \"secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"",
            "",
        );
        assert!(matches!(
            invalid.parse::<Config>(),
            Err(ConfigError::DerivedFromSecretlessRoot { profile, source })
                if (profile == "contributor" || profile == "reader") && source == "developer"
        ));
    }

    #[test]
    fn test_derived_profile_default_repo() {
        let config_str = r#"
version = 1

[profile.developer]
github_app.account = "acme"
github_app.client_id = "id"
github_app.client_secret = "secret"

[profile.reader]
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

    #[test]
    fn test_root_profile_rejects_repository_scope() {
        let config = r#"
version = 1

[profile.developer]
repo = "all"
github_app.account = "acme"
github_app.client_id = "id"
github_app.client_secret = "secret"
"#;
        assert!(matches!(
            config.parse::<Config>(),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn profile_shape_is_strict_and_unambiguous() {
        let invalid_profiles = [
            r#"
version = 1
[profile.developer]
kind = "root"
github_app.account = "acme"
github_app.client_id = "id"
"#,
            r#"
version = 1
[profile.mixed]
source = "developer"
permissions = { contents = "read" }
github_app.account = "acme"
github_app.client_id = "id"
"#,
            r#"
version = 1
[profile.incomplete]
description = "neither root nor derived"
"#,
            r"
version = 1
unexpected = true
",
            r#"
version = 1
[profile.developer]
github_app.account = "acme"
github_app.client_id = "id"
github_app.unknown = "value"
"#,
            r#"
version = 1
[profile.reader]
source = "developer"
permission = { contents = "read" }
"#,
        ];

        for config in invalid_profiles {
            assert!(matches!(
                config.parse::<Config>(),
                Err(ConfigError::Parse(_))
            ));
        }
    }

    #[test]
    fn test_no_browser_config_parsing() {
        let config_str = r#"
version = 1
no_browser = true

[profile.developer]
github_app.account = "acme"
github_app.client_id = "id"
github_app.client_secret = "secret"
"#;
        let config: Config = config_str.parse().unwrap();
        assert!(config.no_browser);

        let default_config: Config = VALID_CONFIG.parse().unwrap();
        assert!(!default_config.no_browser);
    }

    #[test]
    fn test_empty_derived_permissions_disallowed() {
        let invalid_config = r#"
version = 1

[profile.developer]
github_app.account = "acme"
github_app.client_id = "id"
github_app.client_secret = "secret"

[profile.reader]
source = "developer"
permissions = {}
"#;
        let err: ConfigError = invalid_config.parse::<Config>().unwrap_err();
        match err {
            ConfigError::InvalidDerivedProfile { profile, reason } => {
                assert_eq!(profile, "reader");
                assert!(reason.contains("permissions map must not be empty"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn toml_errors_do_not_retain_secret_source() {
        let marker = "secret-marker-must-not-leak";
        let invalid =
            format!("version = 1\n[profile.developer]\ngithub_app.client_secret = \"{marker}\n");
        let error = invalid.parse::<Config>().unwrap_err();
        assert!(!error.to_string().contains(marker));
        assert!(!format!("{error:?}").contains(marker));
        let command_error = crate::cmd::CmdError::from(error);
        assert!(!command_error.to_string().contains(marker));
        assert!(!format!("{command_error:?}").contains(marker));
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_insecure_file_types_links_and_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = tempfile::tempdir().unwrap();
        let valid = temp.path().join("valid.toml");
        std::fs::write(&valid, VALID_CONFIG).unwrap();
        std::fs::set_permissions(&valid, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(Some(&valid)).is_ok());

        std::fs::set_permissions(&valid, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load(Some(&valid)),
            Err(ConfigError::InsecurePath {
                reason: "unexpected permissions",
                ..
            })
        ));
        std::fs::set_permissions(&valid, std::fs::Permissions::from_mode(0o600)).unwrap();

        let symlink_path = temp.path().join("symlink.toml");
        symlink(&valid, &symlink_path).unwrap();
        assert!(load(Some(&symlink_path)).is_err());

        let hardlink_path = temp.path().join("hardlink.toml");
        std::fs::hard_link(&valid, &hardlink_path).unwrap();
        assert!(matches!(
            load(Some(&valid)),
            Err(ConfigError::InsecurePath {
                reason: "hard links are not permitted",
                ..
            })
        ));

        let directory = temp.path().join("directory.toml");
        std::fs::create_dir(&directory).unwrap();
        assert!(matches!(
            load(Some(&directory)),
            Err(ConfigError::InsecurePath {
                reason: "expected a regular file",
                ..
            })
        ));
    }
}
