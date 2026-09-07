use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum FsError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    InsecurePath {
        path: PathBuf,
        reason: &'static str,
    },
    Platform(&'static str),
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "I/O error for '{}': {source}", path.display())
            }
            Self::InsecurePath { path, reason } => {
                write!(f, "insecure path '{}': {reason}", path.display())
            }
            Self::Platform(reason) => write!(f, "filesystem platform error: {reason}"),
        }
    }
}

impl std::error::Error for FsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InsecurePath { .. } | Self::Platform(_) => None,
        }
    }
}
