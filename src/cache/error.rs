use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum CacheError {
    Io(std::io::Error),
    Json(serde_json::Error),
    InsecurePath { path: PathBuf, reason: &'static str },
    InvalidKey(String),
    InvalidTimestamp(String),
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
            Self::InvalidTimestamp(timestamp) => {
                write!(f, "invalid RFC3339 expiry timestamp '{timestamp}' in cache")
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
            | Self::InvalidTimestamp(_)
            | Self::Platform(_) => None,
        }
    }
}
