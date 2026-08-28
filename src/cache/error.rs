use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum CacheError {
    Io(std::io::Error),
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
    EpochChanged {
        expected: u64,
        actual: u64,
    },
    BaseGenerationChanged,
    RenewalEntryChanged,
    UnsupportedSchema {
        kind: String,
        version: Option<u32>,
        expected: u32,
    },
    Platform(&'static str),
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "cache IO error: {err}"),
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
            Self::EpochChanged { expected, actual } => write!(
                f,
                "cache epoch changed from {expected} to {actual} while issuing a token"
            ),
            Self::BaseGenerationChanged => {
                write!(f, "source base generation changed while issuing a token")
            }
            Self::RenewalEntryChanged => {
                write!(f, "scoped cache entry changed while renewing a token")
            }
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

impl std::error::Error for CacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Json(err) => Some(err),
            Self::InsecurePath { .. }
            | Self::InvalidKey(_)
            | Self::InconsistentMetadata { .. }
            | Self::UnexpectedKind { .. }
            | Self::RunCollision(_)
            | Self::InvalidRunTransition(_)
            | Self::MalformedEpoch
            | Self::EpochExhausted
            | Self::EpochChanged { .. }
            | Self::BaseGenerationChanged
            | Self::RenewalEntryChanged
            | Self::UnsupportedSchema { .. }
            | Self::Platform(_) => None,
        }
    }
}
