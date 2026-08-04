use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum ConfigError {
    ConfigDirNotFound,
    CacheDirNotFound,
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse(toml::de::Error),
    UnsupportedVersion(u32),
    MissingDefaultProfile(String),
    ProfileNotFound {
        profile: String,
        source: String,
    },
    DerivedFromNonRoot {
        profile: String,
        source: String,
    },
    DerivedFromSecretlessRoot {
        profile: String,
        source: String,
    },
    InvalidRootProfile {
        profile: String,
        reason: String,
    },
    InvalidDerivedProfile {
        profile: String,
        reason: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigDirNotFound => write!(f, "could not determine user config directory"),
            Self::CacheDirNotFound => write!(f, "could not determine user cache directory"),
            Self::Io { path, source } => {
                write!(f, "IO error reading '{}': {source}", path.display())
            }
            Self::Parse(err) => write!(f, "TOML parse error: {err}"),
            Self::UnsupportedVersion(v) => write!(
                f,
                "unsupported config version {v}, only version 1 is supported"
            ),
            Self::MissingDefaultProfile(p) => {
                write!(f, "default profile '{p}' is not defined in profiles")
            }
            Self::ProfileNotFound { profile, source } => write!(
                f,
                "derived profile '{profile}' references unknown source profile '{source}'"
            ),
            Self::DerivedFromNonRoot { profile, source } => write!(
                f,
                "derived profile '{profile}' references source profile '{source}' which is not a root profile"
            ),
            Self::DerivedFromSecretlessRoot { profile, source } => write!(
                f,
                "derived profile '{profile}' references secretless root profile '{source}'; derived tokens require a client secret"
            ),
            Self::InvalidRootProfile { profile, reason } => {
                write!(f, "invalid root profile '{profile}': {reason}")
            }
            Self::InvalidDerivedProfile { profile, reason } => {
                write!(f, "invalid derived profile '{profile}': {reason}")
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ConfigError;

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
}
