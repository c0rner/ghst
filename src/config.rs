mod error;
mod types;
mod validation;

pub use error::ConfigError;
#[cfg(test)]
use types::PermissionLevel;
pub use types::{Config, DerivedProfile, GitHubAppConfig, ProfileConfig, RepoScope, RootProfile};

#[cfg(unix)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Read, Write};
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
        match fs::symlink_metadata(&self.path) {
            Ok(_) => Ok(true),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(ConfigError::Io {
                path: self.path.clone(),
                source,
            }),
        }
    }

    pub fn initialize(&self) -> Result<bool, ConfigError> {
        ensure_config_parent(self)?;
        if self.exists()? {
            return Ok(false);
        }
        create_initial_config(&self.path)
    }

    pub fn enforce_permissions(&self) -> Result<(), ConfigError> {
        if let Some(directory) = &self.default_directory {
            enforce_config_dir_permissions(directory)?;
        }
        enforce_config_file_permissions(&self.path)
    }

    pub fn load(&self) -> Result<Config, ConfigError> {
        let mut file = match &self.default_directory {
            Some(config_dir) => open_default_config_file(config_dir)?,
            None => open_config_file(&self.path)?,
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
    config_location(path)?.load()
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

#[cfg(unix)]
fn ensure_config_parent(location: &ConfigLocation) -> Result<(), ConfigError> {
    use std::os::unix::fs::DirBuilderExt;

    let directory = location
        .path
        .parent()
        .ok_or_else(|| ConfigError::MissingParent(location.path.clone()))?;
    let directory = if directory.as_os_str().is_empty() {
        Path::new(".")
    } else {
        directory
    };
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(directory)
        .map_err(|source| ConfigError::Io {
            path: directory.to_path_buf(),
            source,
        })?;
    if let Some(default_directory) = &location.default_directory {
        enforce_config_dir_permissions(default_directory)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_config_parent(location: &ConfigLocation) -> Result<(), ConfigError> {
    Err(ConfigError::InsecurePath {
        path: location.path.clone(),
        reason: "secure configuration initialization is not supported on this platform",
    })
}

#[cfg(unix)]
fn create_initial_config(path: &Path) -> Result<bool, ConfigError> {
    use std::os::unix::fs::PermissionsExt;

    let directory = path
        .parent()
        .ok_or_else(|| ConfigError::MissingParent(path.to_path_buf()))?;
    let directory = if directory.as_os_str().is_empty() {
        Path::new(".")
    } else {
        directory
    };
    let mut builder = tempfile::Builder::new();
    builder
        .prefix(".ghst-profiles-")
        .suffix(".tmp")
        .permissions(fs::Permissions::from_mode(0o600));
    let mut temporary = builder
        .tempfile_in(directory)
        .map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    temporary
        .write_all(STARTER_TEMPLATE.as_bytes())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    match temporary.persist_noclobber(path) {
        Ok(_) => {
            sync_directory(directory)?;
            Ok(true)
        }
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(ConfigError::Io {
            path: path.to_path_buf(),
            source: error.error,
        }),
    }
}

#[cfg(not(unix))]
fn create_initial_config(path: &Path) -> Result<bool, ConfigError> {
    Err(ConfigError::InsecurePath {
        path: path.to_path_buf(),
        reason: "secure configuration initialization is not supported on this platform",
    })
}

#[cfg(unix)]
fn open_config_file(path: &Path) -> Result<File, ConfigError> {
    use std::os::unix::fs::OpenOptionsExt;

    let flags = open_flags(path, rustix::fs::OFlags::NOFOLLOW)?;
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
    validate_config_file_metadata(path, &metadata, rustix::process::geteuid().as_raw())?;
    Ok(file)
}

#[cfg(unix)]
fn open_default_config_file(config_dir: &Path) -> Result<File, ConfigError> {
    use std::os::unix::fs::OpenOptionsExt;

    let metadata = std::fs::symlink_metadata(config_dir).map_err(|source| ConfigError::Io {
        path: config_dir.to_path_buf(),
        source,
    })?;
    let effective_uid = rustix::process::geteuid().as_raw();
    validate_config_dir_metadata(config_dir, &metadata, effective_uid)?;

    let flags = open_flags(
        config_dir,
        rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW,
    )?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(config_dir)
        .map_err(|source| ConfigError::Io {
            path: config_dir.to_path_buf(),
            source,
        })?;
    let metadata = directory.metadata().map_err(|source| ConfigError::Io {
        path: config_dir.to_path_buf(),
        source,
    })?;
    validate_config_dir_metadata(config_dir, &metadata, effective_uid)?;

    let path = config_dir.join(CONFIG_FILE);
    let descriptor = rustix::fs::openat(
        &directory,
        CONFIG_FILE,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| ConfigError::Io {
        path: path.clone(),
        source: source.into(),
    })?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|source| ConfigError::Io {
        path: path.clone(),
        source,
    })?;
    validate_config_file_metadata(&path, &metadata, effective_uid)?;
    Ok(file)
}

#[cfg(unix)]
fn validate_config_file_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
    effective_uid: u32,
) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;

    validate_config_file_identity(path, metadata, effective_uid)?;
    let reason = if metadata.permissions().mode() & 0o7777 == 0o600 {
        None
    } else {
        Some("unexpected permissions")
    };
    reason.map_or_else(
        || Ok(()),
        |reason| {
            Err(ConfigError::InsecurePath {
                path: path.to_path_buf(),
                reason,
            })
        },
    )
}

#[cfg(unix)]
fn validate_config_dir_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
    effective_uid: u32,
) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;

    validate_config_dir_identity(path, metadata, effective_uid)?;
    let reason = if metadata.permissions().mode() & 0o7777 == 0o700 {
        None
    } else {
        Some("unexpected permissions")
    };
    reason.map_or_else(
        || Ok(()),
        |reason| {
            Err(ConfigError::InsecurePath {
                path: path.to_path_buf(),
                reason,
            })
        },
    )
}

#[cfg(unix)]
fn enforce_config_file_permissions(path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::OpenOptionsExt;

    let flags = open_flags(
        path,
        rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK,
    )?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    repair_config_file_permissions(path, &file, rustix::process::geteuid().as_raw())
}

#[cfg(unix)]
fn repair_config_file_permissions(
    path: &Path,
    file: &File,
    effective_uid: u32,
) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = file.metadata().map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_config_file_identity(path, &metadata, effective_uid)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata = file.metadata().map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_config_file_metadata(path, &metadata, effective_uid)
}

#[cfg(unix)]
fn validate_config_file_identity(
    path: &Path,
    metadata: &fs::Metadata,
    effective_uid: u32,
) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;

    let reason = if !metadata.is_file() {
        Some("expected a regular file")
    } else if metadata.nlink() != 1 {
        Some("hard links are not permitted")
    } else if metadata.uid() != effective_uid {
        Some("not owned by the effective user")
    } else {
        None
    };
    reason.map_or_else(
        || Ok(()),
        |reason| {
            Err(ConfigError::InsecurePath {
                path: path.to_path_buf(),
                reason,
            })
        },
    )
}

#[cfg(unix)]
fn enforce_config_dir_permissions(path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::OpenOptionsExt;

    let flags = open_flags(
        path,
        rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK,
    )?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    repair_config_dir_permissions(path, &directory, rustix::process::geteuid().as_raw())
}

#[cfg(unix)]
fn repair_config_dir_permissions(
    path: &Path,
    directory: &File,
    effective_uid: u32,
) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = directory.metadata().map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_config_dir_identity(path, &metadata, effective_uid)?;
    directory
        .set_permissions(fs::Permissions::from_mode(0o700))
        .map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata = directory.metadata().map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_config_dir_metadata(path, &metadata, effective_uid)
}

#[cfg(unix)]
fn validate_config_dir_identity(
    path: &Path,
    metadata: &fs::Metadata,
    effective_uid: u32,
) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;

    let reason = if metadata.file_type().is_symlink() {
        Some("symbolic links are not permitted")
    } else if !metadata.is_dir() {
        Some("expected a directory")
    } else if metadata.uid() != effective_uid {
        Some("not owned by the effective user")
    } else {
        None
    };
    reason.map_or_else(
        || Ok(()),
        |reason| {
            Err(ConfigError::InsecurePath {
                path: path.to_path_buf(),
                reason,
            })
        },
    )
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::OpenOptionsExt;

    let flags = open_flags(
        path,
        rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW,
    )?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    directory.sync_all().map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn enforce_config_file_permissions(path: &Path) -> Result<(), ConfigError> {
    Err(ConfigError::InsecurePath {
        path: path.to_path_buf(),
        reason: "secure configuration editing is not supported on this platform",
    })
}

#[cfg(not(unix))]
fn enforce_config_dir_permissions(path: &Path) -> Result<(), ConfigError> {
    Err(ConfigError::InsecurePath {
        path: path.to_path_buf(),
        reason: "secure configuration editing is not supported on this platform",
    })
}

#[cfg(unix)]
fn open_flags(path: &Path, flags: rustix::fs::OFlags) -> Result<i32, ConfigError> {
    i32::try_from(flags.bits()).map_err(|_| ConfigError::InsecurePath {
        path: path.to_path_buf(),
        reason: "required filesystem open flags are not supported",
    })
}

#[cfg(not(unix))]
fn open_config_file(path: &Path) -> Result<File, ConfigError> {
    Err(ConfigError::InsecurePath {
        path: path.to_path_buf(),
        reason: "secure configuration loading is not supported on this platform",
    })
}

#[cfg(not(unix))]
fn open_default_config_file(config_dir: &Path) -> Result<File, ConfigError> {
    Err(ConfigError::InsecurePath {
        path: config_dir.to_path_buf(),
        reason: "secure configuration loading is not supported on this platform",
    })
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
    fn starter_template_is_a_valid_configuration() {
        let config: Config = STARTER_TEMPLATE.parse().unwrap();
        assert_eq!(config.default_profile.as_deref(), Some("contributor"));
        assert!(matches!(
            config.profiles.get("developer"),
            Some(ProfileConfig::Root(_))
        ));
        assert!(matches!(
            config.profiles.get("reader"),
            Some(ProfileConfig::Derived(_))
        ));
    }

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
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

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

        let metadata = std::fs::metadata(&valid).unwrap();
        assert!(matches!(
            validate_config_file_metadata(&valid, &metadata, metadata.uid().wrapping_add(1)),
            Err(ConfigError::InsecurePath {
                reason: "not owned by the effective user",
                ..
            })
        ));

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
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

        let temp = tempfile::tempdir().unwrap();
        let config_dir = temp.path().join(CONFIG_DIRECTORY);
        std::fs::create_dir(&config_dir).unwrap();
        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config_file = config_dir.join(CONFIG_FILE);
        std::fs::write(&config_file, VALID_CONFIG).unwrap();
        std::fs::set_permissions(&config_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(open_default_config_file(&config_dir).is_ok());

        let metadata = std::fs::metadata(&config_dir).unwrap();
        assert!(matches!(
            validate_config_dir_metadata(&config_dir, &metadata, metadata.uid().wrapping_add(1)),
            Err(ConfigError::InsecurePath {
                reason: "not owned by the effective user",
                ..
            })
        ));

        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            open_default_config_file(&config_dir),
            Err(ConfigError::InsecurePath {
                reason: "unexpected permissions",
                ..
            })
        ));
        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let symlink_dir = temp.path().join("linked-ghst");
        symlink(&config_dir, &symlink_dir).unwrap();
        assert!(matches!(
            open_default_config_file(&symlink_dir),
            Err(ConfigError::InsecurePath {
                reason: "symbolic links are not permitted",
                ..
            })
        ));

        let regular_file = temp.path().join("not-a-directory");
        std::fs::write(&regular_file, "not a directory").unwrap();
        assert!(matches!(
            open_default_config_file(&regular_file),
            Err(ConfigError::InsecurePath {
                reason: "expected a directory",
                ..
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn explicit_config_path_does_not_require_a_private_parent_directory() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let custom_dir = temp.path().join("custom");
        std::fs::create_dir(&custom_dir).unwrap();
        std::fs::set_permissions(&custom_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config_file = custom_dir.join("custom.toml");
        std::fs::write(&config_file, VALID_CONFIG).unwrap();
        std::fs::set_permissions(&config_file, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(load(Some(&config_file)).is_ok());
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

    #[cfg(unix)]
    #[test]
    fn permission_repair_validates_descriptors_before_mutation() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        let config_file = temp.path().join(CONFIG_FILE);
        std::fs::write(&config_file, STARTER_TEMPLATE).unwrap();
        std::fs::set_permissions(&config_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let file = File::open(&config_file).unwrap();
        let wrong_uid = file.metadata().unwrap().uid().wrapping_add(1);

        assert!(matches!(
            repair_config_file_permissions(&config_file, &file, wrong_uid),
            Err(ConfigError::InsecurePath {
                reason: "not owned by the effective user",
                ..
            })
        ));
        assert_eq!(
            file.metadata().unwrap().permissions().mode() & 0o7777,
            0o644
        );

        let directory = temp.path().join(CONFIG_DIRECTORY);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let descriptor = File::open(&directory).unwrap();
        let wrong_uid = descriptor.metadata().unwrap().uid().wrapping_add(1);

        assert!(matches!(
            repair_config_dir_permissions(&directory, &descriptor, wrong_uid),
            Err(ConfigError::InsecurePath {
                reason: "not owned by the effective user",
                ..
            })
        ));
        assert_eq!(
            descriptor.metadata().unwrap().permissions().mode() & 0o7777,
            0o755
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

        assert!(matches!(
            enforce_config_file_permissions(&fifo),
            Err(ConfigError::InsecurePath {
                reason: "expected a regular file",
                ..
            })
        ));
    }
}
