use std::fmt;

#[derive(Debug)]
pub enum GitHubError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Http {
        status: u16,
        message: String,
    },
    OAuthPending,
    OAuthSlowDown,
    OAuthExpired,
    OAuthAccessDenied,
    OAuthError {
        error: String,
        description: Option<String>,
    },
}

impl fmt::Display for GitHubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "IO error: {err}"),
            Self::Json(err) => write!(f, "JSON error: {err}"),
            Self::Http { status, message } => write!(f, "HTTP status {status}: {message}"),
            Self::OAuthPending => write!(f, "authorization pending"),
            Self::OAuthSlowDown => write!(f, "slow down polling rate"),
            Self::OAuthExpired => write!(f, "device code expired"),
            Self::OAuthAccessDenied => write!(f, "user denied access request"),
            Self::OAuthError { error, description } => match description {
                Some(desc) => write!(f, "OAuth error '{error}': {desc}"),
                None => write!(f, "OAuth error '{error}'"),
            },
        }
    }
}

impl std::error::Error for GitHubError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Json(err) => Some(err),
            _ => None,
        }
    }
}
