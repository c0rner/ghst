use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum CacheError {
    Io {
        path: Option<PathBuf>,
        source: std::io::Error,
    },
    Json(serde_json::Error),
    InsecurePath {
        path: PathBuf,
        reason: &'static str,
    },
    InvalidKey(String),
    InconsistentMetadata {
        expected_key: String,
        actual_key: String,
    },
    UnexpectedKind {
        expected: &'static str,
        actual: &'static str,
    },
    RunCollision(String),
    InvalidRunTransition(&'static str),
    MalformedEpoch,
    EpochExhausted,
    UnsupportedSchema {
        kind: String,
        version: Option<u32>,
        expected: u32,
    },
    Platform(&'static str),
}

impl CacheError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: Some(path.into()),
            source,
        }
    }

    pub const fn descriptor_io(source: std::io::Error) -> Self {
        Self::Io { path: None, source }
    }
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                path: Some(path),
                source,
            } => write!(f, "cache IO error for '{}': {source}", path.display()),
            Self::Io { path: None, source } => write!(f, "cache IO error: {source}"),
            Self::Json(err) => write!(f, "cache JSON error: {err}"),
            Self::InsecurePath { path, reason } => {
                write!(f, "insecure cache path '{}': {reason}", path.display())
            }
            Self::InvalidKey(key) => write!(f, "invalid cache key '{key}'"),
            Self::InconsistentMetadata {
                expected_key,
                actual_key,
            } => write!(
                f,
                "cache entry metadata resolves to key '{actual_key}', expected '{expected_key}'"
            ),
            Self::UnexpectedKind { expected, actual } => {
                write!(
                    f,
                    "unexpected cache entry kind '{actual}', expected '{expected}'"
                )
            }
            Self::RunCollision(key) => write!(f, "run cache key collision at '{key}'"),
            Self::InvalidRunTransition(reason) => {
                write!(f, "invalid run cache lifecycle transition: {reason}")
            }
            Self::MalformedEpoch => write!(f, "cache lock contains a malformed epoch"),
            Self::EpochExhausted => write!(f, "cache epoch is exhausted"),
            Self::UnsupportedSchema {
                kind,
                version: Some(version),
                expected,
            } => write!(
                f,
                "unsupported {kind} cache schema version {version}, expected {expected}"
            ),
            Self::UnsupportedSchema {
                kind,
                version: None,
                expected,
            } => write!(
                f,
                "missing {kind} cache schema version, expected {expected}"
            ),
            Self::Platform(reason) => write!(f, "cache platform error: {reason}"),
        }
    }
}

impl From<crate::fs::FsError> for CacheError {
    fn from(source: crate::fs::FsError) -> Self {
        match source {
            crate::fs::FsError::Io { path, source } => Self::Io {
                path: Some(path),
                source,
            },
            crate::fs::FsError::InsecurePath { path, reason } => {
                Self::InsecurePath { path, reason }
            }
            crate::fs::FsError::Platform(reason) => Self::Platform(reason),
        }
    }
}

impl From<crate::run::RunTransitionError> for CacheError {
    fn from(error: crate::run::RunTransitionError) -> Self {
        match error {
            crate::run::RunTransitionError::PendingOwnership => {
                Self::InvalidRunTransition("pending run ownership did not match")
            }
            crate::run::RunTransitionError::ReleasedOwnership => {
                Self::InvalidRunTransition("released run ownership did not match")
            }
            crate::run::RunTransitionError::AbandonedRun => {
                Self::InvalidRunTransition("abandoned run changed while checking liveness")
            }
            crate::run::RunTransitionError::CleanupDeletion => {
                Self::InvalidRunTransition("cleanup deletion ownership did not match")
            }
        }
    }
}

impl std::error::Error for CacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json(err) => Some(err),
            Self::InsecurePath { .. }
            | Self::InvalidKey(_)
            | Self::InconsistentMetadata { .. }
            | Self::UnexpectedKind { .. }
            | Self::RunCollision(_)
            | Self::InvalidRunTransition(_)
            | Self::MalformedEpoch
            | Self::EpochExhausted
            | Self::UnsupportedSchema { .. }
            | Self::Platform(_) => None,
        }
    }
}
