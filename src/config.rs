mod error;
mod types;
mod validation;

pub use error::ConfigError;
pub use types::{AppProfile, Config, GitHubAppConfig, ProfileConfig};

use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;

const CONFIG_DIRECTORY: &str = "ghst";
const CONFIG_FILE: &str = "profiles.toml";

pub const STARTER_TEMPLATE: &str = include_str!("../profiles.toml");

pub struct ConfigLocation {
    path: PathBuf,
    default_directory: Option<PathBuf>,
}

impl ConfigLocation {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> Result<bool, ConfigError> {
        crate::fs::symlink_exists(&self.path).map_err(ConfigError::from)
    }

    pub fn initialize(&self) -> Result<bool, ConfigError> {
        ensure_config_parent(self)?;
        if self.exists()? {
            return Ok(false);
        }
        crate::fs::publish_if_absent(&self.path, STARTER_TEMPLATE.as_bytes())
            .map_err(ConfigError::from)
    }

    pub fn enforce_permissions(&self) -> Result<(), ConfigError> {
        if let Some(directory) = &self.default_directory {
            crate::fs::repair_dir_permissions(directory)?;
        }
        crate::fs::repair_file_permissions(&self.path)?;
        Ok(())
    }

    pub fn load(&self) -> Result<Config, ConfigError> {
        let mut file = match &self.default_directory {
            Some(config_dir) => {
                let dir = crate::fs::open_private_dir(config_dir)?;
                crate::fs::open_private_child(config_dir, &dir, Path::new(CONFIG_FILE))?
            }
            None => crate::fs::open_private_file(&self.path)?,
        };
        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|source| ConfigError::Io {
                path: self.path.clone(),
                source,
            })?;
        content.parse()
    }
}

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
    let location = config_location(path)?;
    tracing::debug!(path = %location.path().display(), "loading configuration");
    let config = location.load()?;
    tracing::debug!(
        path = %location.path().display(),
        version = config.version,
        profiles = config.profiles.len(),
        default_profile = config.default_profile.as_deref().unwrap_or("<unset>"),
        "configuration loaded and validated"
    );
    Ok(config)
}

pub fn config_location(path: Option<&Path>) -> Result<ConfigLocation, ConfigError> {
    path.map(Path::to_path_buf)
        .or_else(|| std::env::var_os("GHST_CONFIG").map(PathBuf::from))
        .map_or_else(
            || {
                sysdirs::config_dir()
                    .ok_or(ConfigError::ConfigDirNotFound)
                    .map(|path| {
                        let directory = path.join(CONFIG_DIRECTORY);
                        ConfigLocation {
                            path: directory.join(CONFIG_FILE),
                            default_directory: Some(directory),
                        }
                    })
            },
            |path| {
                Ok(ConfigLocation {
                    path,
                    default_directory: None,
                })
            },
        )
}

fn ensure_config_parent(location: &ConfigLocation) -> Result<(), ConfigError> {
    let directory = location
        .path
        .parent()
        .ok_or_else(|| ConfigError::MissingParent(location.path.clone()))?;
    let directory = if directory.as_os_str().is_empty() {
        Path::new(".")
    } else {
        directory
    };
    crate::fs::create_private_dir(directory)?;
    if let Some(default_directory) = &location.default_directory {
        crate::fs::repair_dir_permissions(default_directory)?;
    }
    Ok(())
}

/// Returns the cache directory path.
///
/// # Errors
///
/// Returns `ConfigError::CacheDirNotFound` if `GHST_CACHE_DIR` is unset and the user cache directory cannot be resolved.
pub fn cache_dir() -> Result<PathBuf, ConfigError> {
    if let Some(value) = std::env::var_os("GHST_CACHE_DIR") {
        let path = PathBuf::from(value);
        tracing::debug!(path = %path.display(), source = "environment", "resolved cache directory");
        return Ok(path);
    }
    let cache_dir = sysdirs::cache_dir().ok_or(ConfigError::CacheDirNotFound)?;
    let path = cache_dir.join("ghst");
    tracing::debug!(path = %path.display(), source = "platform_default", "resolved cache directory");
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::profile::{PermissionLevel, RepoScope, ResolvedTokenProfile};

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
    fn starter_template_is_a_valid_configuration() {
        let config: Config = STARTER_TEMPLATE.parse().unwrap();
        assert_eq!(config.default_profile.as_deref(), Some("contributor"));
        assert!(matches!(
            config.profiles.get("developer"),
            Some(ProfileConfig::App(_))
        ));
        assert!(matches!(
            config.profiles.get("reader"),
            Some(ProfileConfig::Scoped(_))
        ));
    }

    #[test]
    fn test_valid_config_parsing() {
        let config: Config = VALID_CONFIG.parse().unwrap();
        assert_eq!(config.version, 1);
        assert_eq!(config.default_profile.as_deref(), Some("reader"));

        let dev_profile = config.profiles.get("developer").unwrap();
        match dev_profile {
            ProfileConfig::App(app) => {
                assert_eq!(app.github_app.account, "acme-corp");
                assert_eq!(app.github_app.client_id, "Iv1.8888888888888888");
                assert_eq!(
                    app.github_app.client_secret.as_deref(),
                    Some("secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
                );
            }
            ProfileConfig::Scoped(_) => panic!("expected app profile"),
        }

        let reader_profile = config.profiles.get("reader").unwrap();
        match reader_profile {
            ProfileConfig::Scoped(scoped) => {
                assert_eq!(scoped.source, "developer");
                assert_eq!(scoped.repo, RepoScope::Auto);
                assert_eq!(
                    scoped.permissions.get("contents"),
                    Some(&PermissionLevel::Read)
                );
            }
            ProfileConfig::App(_) => panic!("expected scoped profile"),
        }

        let sec_reviewer = config.profiles.get("security-reviewer").unwrap();
        match sec_reviewer {
            ProfileConfig::Scoped(scoped) => {
                assert_eq!(scoped.source, "security-admin");
                assert_eq!(scoped.repo, RepoScope::Specific("octo-org/api".to_string()));
                assert_eq!(
                    scoped.permissions.get("vulnerability_alerts"),
                    Some(&PermissionLevel::Read)
                );
            }
            ProfileConfig::App(_) => panic!("expected scoped profile"),
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
    fn test_scoped_chaining_disallowed() {
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
            ConfigError::ScopedFromNonApp { profile, source } => {
                assert_eq!(profile, "sub_reader");
                assert_eq!(source, "reader");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn scoped_profile_source_must_exist() {
        let config = r#"
version = 1

[profile.reader]
source = "missing"
permissions = { contents = "read" }
"#;
        assert!(matches!(
            config.parse::<Config>(),
            Err(ConfigError::ScopedSourceNotFound { profile, source })
                if profile == "reader" && source == "missing"
        ));
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
    fn standalone_secretless_app_can_be_default() {
        let config: Config = r#"
version = 1
default_profile = "developer"

[profile.developer]
github_app.account = "acme"
github_app.client_id = "id"
"#
        .parse()
        .unwrap();
        let ProfileConfig::App(app) = config.profiles.get("developer").unwrap() else {
            panic!("expected app profile");
        };
        assert_eq!(app.github_app.client_secret, None);
        assert!(format!("{config:?}").contains("client_secret: None"));
    }

    #[test]
    fn empty_configured_secret_is_invalid() {
        let invalid = VALID_CONFIG.replace("secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "   ");
        assert!(matches!(
            invalid.parse::<Config>(),
            Err(ConfigError::InvalidAppProfile { .. })
        ));
    }

    #[test]
    fn scoped_profile_cannot_reference_secretless_app() {
        let invalid = VALID_CONFIG.replace(
            "github_app.client_secret = \"secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"",
            "",
        );
        assert!(matches!(
            invalid.parse::<Config>(),
            Err(ConfigError::ScopedFromSecretlessApp { profile, source })
                if (profile == "contributor" || profile == "reader") && source == "developer"
        ));
    }

    #[test]
    fn test_scoped_profile_default_repo() {
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
            ProfileConfig::Scoped(scoped) => {
                assert_eq!(scoped.repo, RepoScope::Auto);
            }
            ProfileConfig::App(_) => panic!("expected scoped profile"),
        }
    }

    #[test]
    fn scoped_profile_accepts_multiple_repository_selections() {
        let config: Config = VALID_CONFIG
            .replace(
                "repo = \"auto\"",
                "repo = [\"acme/application\", \"acme/shared-library\", \"auto\"]",
            )
            .parse()
            .unwrap();
        let ProfileConfig::Scoped(reader) = config.profiles.get("reader").unwrap() else {
            panic!("expected scoped profile");
        };
        assert_eq!(
            reader.repo,
            RepoScope::Multiple(Vec::from([
                "acme/application".to_owned(),
                "acme/shared-library".to_owned(),
                "auto".to_owned(),
            ]))
        );

        let invalid = VALID_CONFIG.replace("repo = \"auto\"", "repo = [\"acme/api\", 1]");
        assert!(matches!(
            invalid.parse::<Config>(),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn test_app_profile_rejects_repository_scope() {
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
kind = "app"
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
description = "neither app nor scoped"
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
    fn test_empty_scoped_permissions_disallowed() {
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
            ConfigError::InvalidScopedProfile { profile, reason } => {
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

    #[cfg(unix)]
    #[test]
    fn default_config_directory_must_be_private_owned_and_not_a_symlink() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = tempfile::tempdir().unwrap();
        let config_dir = temp.path().join(CONFIG_DIRECTORY);
        std::fs::create_dir(&config_dir).unwrap();
        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config_file = config_dir.join(CONFIG_FILE);
        std::fs::write(&config_file, VALID_CONFIG).unwrap();
        std::fs::set_permissions(&config_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let location = ConfigLocation {
            path: config_file,
            default_directory: Some(config_dir.clone()),
        };
        assert!(location.load().is_ok());

        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            location.load(),
            Err(ConfigError::InsecurePath {
                reason: "unexpected permissions",
                ..
            })
        ));
        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let symlink_dir = temp.path().join("linked-ghst");
        symlink(&config_dir, &symlink_dir).unwrap();
        let symlink_location = ConfigLocation {
            path: symlink_dir.join(CONFIG_FILE),
            default_directory: Some(symlink_dir),
        };
        assert!(matches!(
            symlink_location.load(),
            Err(ConfigError::InsecurePath {
                reason: "symbolic links are not permitted",
                ..
            })
        ));

        let regular_file = temp.path().join("not-a-directory");
        std::fs::write(&regular_file, "not a directory").unwrap();
        let file_location = ConfigLocation {
            path: regular_file.join(CONFIG_FILE),
            default_directory: Some(regular_file),
        };
        assert!(matches!(
            file_location.load(),
            Err(ConfigError::InsecurePath {
                reason: "expected a directory",
                ..
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn explicit_config_path_initializes_and_loads_without_a_private_parent_directory() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let custom_dir = temp.path().join("custom");
        std::fs::create_dir(&custom_dir).unwrap();
        std::fs::set_permissions(&custom_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config_file = custom_dir.join("custom.toml");
        let location = config_location(Some(&config_file)).unwrap();

        assert!(location.initialize().unwrap());
        assert_eq!(
            std::fs::metadata(&custom_dir).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        assert!(location.load().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn initialization_is_private_atomic_and_non_destructive() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let config_file = temp.path().join("new").join("ghst").join(CONFIG_FILE);
        let location = config_location(Some(&config_file)).unwrap();

        assert!(location.initialize().unwrap());
        assert_eq!(
            std::fs::read_to_string(&config_file).unwrap(),
            STARTER_TEMPLATE
        );
        assert_eq!(
            std::fs::metadata(config_file.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&config_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );

        std::fs::write(&config_file, "existing credentials").unwrap();
        assert!(!location.initialize().unwrap());
        assert_eq!(
            std::fs::read_to_string(config_file).unwrap(),
            "existing credentials"
        );
    }

    #[cfg(unix)]
    #[test]
    fn initialization_repairs_an_existing_default_directory() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join(CONFIG_DIRECTORY);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let location = ConfigLocation {
            path: directory.join(CONFIG_FILE),
            default_directory: Some(directory.clone()),
        };

        assert!(location.initialize().unwrap());
        assert_eq!(
            std::fs::metadata(directory).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        assert!(location.load().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn initialization_reports_the_failed_tempfile_directory() {
        let temp = tempfile::tempdir().unwrap();
        let not_a_directory = temp.path().join("not-a-directory");
        std::fs::write(&not_a_directory, "regular file").unwrap();
        let config_file = not_a_directory.join(CONFIG_FILE);
        let location = config_location(Some(&config_file)).unwrap();

        assert!(matches!(
            location.initialize(),
            Err(ConfigError::Io { path, .. }) if path == not_a_directory
        ));
    }

    #[cfg(unix)]
    #[test]
    fn editing_repairs_default_directory_and_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join(CONFIG_DIRECTORY);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = directory.join(CONFIG_FILE);
        std::fs::write(&path, STARTER_TEMPLATE).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let location = ConfigLocation {
            path,
            default_directory: Some(directory.clone()),
        };

        location.enforce_permissions().unwrap();
        location.load().unwrap();
        assert_eq!(
            std::fs::metadata(directory).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(location.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn permission_repair_does_not_follow_a_rewritten_symlink() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.toml");
        std::fs::write(&target, STARTER_TEMPLATE).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let config_file = temp.path().join(CONFIG_FILE);
        symlink(&target, &config_file).unwrap();
        let location = config_location(Some(&config_file)).unwrap();

        assert!(location.enforce_permissions().is_err());
        assert_eq!(
            std::fs::metadata(target).unwrap().permissions().mode() & 0o7777,
            0o644
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn permission_repair_rejects_a_fifo_without_blocking() {
        let temp = tempfile::tempdir().unwrap();
        let fifo = temp.path().join("profiles.fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RWXU,
            0,
        )
        .unwrap();

        let location = ConfigLocation {
            path: fifo,
            default_directory: None,
        };
        assert!(matches!(
            location.enforce_permissions(),
            Err(ConfigError::InsecurePath {
                reason: "expected a regular file",
                ..
            })
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn configuration_loaders_reject_fifos_without_blocking() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let custom_fifo = temp.path().join("custom.fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &custom_fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RWXU,
            0,
        )
        .unwrap();
        std::fs::set_permissions(&custom_fifo, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            load(Some(&custom_fifo)),
            Err(ConfigError::InsecurePath {
                reason: "expected a regular file",
                ..
            })
        ));

        let config_dir = temp.path().join(CONFIG_DIRECTORY);
        std::fs::create_dir(&config_dir).unwrap();
        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let default_fifo = config_dir.join(CONFIG_FILE);
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &default_fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RWXU,
            0,
        )
        .unwrap();
        std::fs::set_permissions(&default_fifo, std::fs::Permissions::from_mode(0o600)).unwrap();
        let default_location = ConfigLocation {
            path: default_fifo,
            default_directory: Some(config_dir),
        };
        assert!(matches!(
            default_location.load(),
            Err(ConfigError::InsecurePath {
                reason: "expected a regular file",
                ..
            })
        ));
    }

    #[test]
    fn test_resolve_token_profile_base_and_scoped() {
        let config: Config = VALID_CONFIG.parse().unwrap();

        let dev = config.resolve_token_profile("developer").unwrap();
        match dev {
            ResolvedTokenProfile::Base { name, app } => {
                assert_eq!(name, "developer");
                assert_eq!(app.authority.account, "acme-corp");
                assert_eq!(app.authority.client_id, "Iv1.8888888888888888");
                assert_eq!(
                    app.client_secret,
                    Some("secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
                );
            }
            ResolvedTokenProfile::Scoped { .. } => panic!("expected base profile"),
        }

        let reader = config.resolve_token_profile("reader").unwrap();
        match reader {
            ResolvedTokenProfile::Scoped {
                name,
                source_name,
                app,
                repository_scope,
                permissions,
            } => {
                assert_eq!(name, "reader");
                assert_eq!(source_name, "developer");
                assert_eq!(app.authority.account, "acme-corp");
                assert_eq!(app.authority.client_id, "Iv1.8888888888888888");
                assert_eq!(app.client_secret, "secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
                assert_eq!(*repository_scope, RepoScope::Auto);
                assert_eq!(permissions.get("contents"), Some(&PermissionLevel::Read));
            }
            ResolvedTokenProfile::Base { .. } => panic!("expected scoped profile"),
        }

        let resolved_with_temporary_lookup = {
            let lookup = String::from("reader");
            config.resolve_token_profile(&lookup).unwrap()
        };
        match resolved_with_temporary_lookup {
            ResolvedTokenProfile::Scoped { name, .. } => assert_eq!(name, "reader"),
            ResolvedTokenProfile::Base { .. } => panic!("expected scoped profile"),
        }
    }

    #[test]
    fn test_resolve_token_profile_fail_closed_validation() {
        let config: Config = VALID_CONFIG.parse().unwrap();

        let err = config.resolve_token_profile("unknown").unwrap_err();
        assert!(matches!(err, ConfigError::ProfileNotFound(ref p) if p == "unknown"));

        let mut malformed = config;
        if let Some(ProfileConfig::Scoped(scoped)) = malformed.profiles.get_mut("reader") {
            scoped.source = "missing-source".to_owned();
        }
        let err = malformed.resolve_token_profile("reader").unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ScopedSourceNotFound {
                ref profile,
                ref source
            } if profile == "reader" && source == "missing-source"
        ));

        if let Some(ProfileConfig::Scoped(scoped)) = malformed.profiles.get_mut("reader") {
            scoped.source = "security-reviewer".to_owned();
        }
        let err = malformed.resolve_token_profile("reader").unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ScopedFromNonApp {
                ref profile,
                ref source
            } if profile == "reader" && source == "security-reviewer"
        ));

        let mut bypass = VALID_CONFIG.parse::<Config>().unwrap();
        if let Some(ProfileConfig::App(app)) = bypass.profiles.get_mut("developer") {
            app.github_app.client_secret = None;
        }
        let err = bypass.resolve_token_profile("reader").unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ScopedFromSecretlessApp {
                ref profile,
                ref source
            } if profile == "reader" && source == "developer"
        ));
    }
}
