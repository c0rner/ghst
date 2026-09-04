use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum ConfigError {
    ConfigDirNotFound,
    CacheDirNotFound,
    MissingParent(PathBuf),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    InsecurePath {
        path: PathBuf,
        reason: &'static str,
    },
    Parse(toml::de::Error),
    UnsupportedVersion(u32),
    MissingDefaultProfile(String),
    ProfileNotFound(String),
    ScopedSourceNotFound {
        profile: String,
        source: String,
    },
    ScopedFromNonApp {
        profile: String,
        source: String,
    },
    ScopedFromSecretlessApp {
        profile: String,
        source: String,
    },
    InvalidAppProfile {
        profile: String,
        reason: String,
    },
    InvalidScopedProfile {
        profile: String,
        reason: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigDirNotFound => write!(f, "could not determine user config directory"),
            Self::CacheDirNotFound => write!(f, "could not determine user cache directory"),
            Self::MissingParent(path) => write!(
                f,
                "configuration path '{}' has no parent directory",
                path.display()
            ),
            Self::Io { path, source } => {
                write!(f, "I/O error for '{}': {source}", path.display())
            }
            Self::InsecurePath { path, reason } => {
                write!(
                    f,
                    "insecure configuration path '{}': {reason}",
                    path.display()
                )
            }
            Self::Parse(err) => write!(f, "TOML parse error: {err}"),
            Self::UnsupportedVersion(v) => write!(
                f,
                "unsupported config version {v}, only version 1 is supported"
            ),
            Self::MissingDefaultProfile(p) => {
                write!(f, "default profile '{p}' is not defined in profiles")
            }
            Self::ProfileNotFound(profile) => {
                write!(f, "profile '{profile}' is not defined in configuration")
            }
            Self::ScopedSourceNotFound { profile, source } => write!(
                f,
                "scoped profile '{profile}' references unknown source profile '{source}'"
            ),
            Self::ScopedFromNonApp { profile, source } => write!(
                f,
                "scoped profile '{profile}' references source profile '{source}' which is not an app profile"
            ),
            Self::ScopedFromSecretlessApp { profile, source } => write!(
                f,
                "scoped profile '{profile}' references secretless app profile '{source}'; scoped tokens require a client secret"
            ),
            Self::InvalidAppProfile { profile, reason } => {
                write!(f, "invalid app profile '{profile}': {reason}")
            }
            Self::InvalidScopedProfile { profile, reason } => {
                write!(f, "invalid scoped profile '{profile}': {reason}")
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse(err) => Some(err),
            Self::ConfigDirNotFound
            | Self::CacheDirNotFound
            | Self::MissingParent(_)
            | Self::InsecurePath { .. }
            | Self::UnsupportedVersion(_)
            | Self::MissingDefaultProfile(_)
            | Self::ProfileNotFound(_)
            | Self::ScopedSourceNotFound { .. }
            | Self::ScopedFromNonApp { .. }
            | Self::ScopedFromSecretlessApp { .. }
            | Self::InvalidAppProfile { .. }
            | Self::InvalidScopedProfile { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ConfigError;
    use std::path::PathBuf;

    #[test]
    fn directory_resolution_errors_are_distinct() {
        assert_eq!(
            ConfigError::ConfigDirNotFound.to_string(),
            "could not determine user config directory"
        );
        assert_eq!(
            ConfigError::CacheDirNotFound.to_string(),
            "could not determine user cache directory"
        );
    }

    #[test]
    fn io_errors_do_not_misreport_the_operation() {
        let error = ConfigError::Io {
            path: PathBuf::from("/tmp/profiles.toml"),
            source: std::io::Error::other("disk full"),
        };
        assert_eq!(
            error.to_string(),
            "I/O error for '/tmp/profiles.toml': disk full"
        );
    }
}
