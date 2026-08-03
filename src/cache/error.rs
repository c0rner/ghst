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
    MalformedEpoch,
    EpochExhausted,
    EpochChanged {
        expected: u64,
        actual: u64,
    },
    RootGenerationChanged,
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
            Self::MalformedEpoch => write!(f, "cache lock contains a malformed epoch"),
            Self::EpochExhausted => write!(f, "cache epoch is exhausted"),
            Self::EpochChanged { expected, actual } => write!(
                f,
                "cache epoch changed from {expected} to {actual} while issuing a token"
            ),
            Self::RootGenerationChanged => {
                write!(f, "source root generation changed while issuing a token")
            }
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
            | Self::MalformedEpoch
            | Self::EpochExhausted
            | Self::EpochChanged { .. }
            | Self::RootGenerationChanged
            | Self::Platform(_) => None,
        }
    }
}
