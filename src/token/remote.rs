use std::fmt;

#[derive(Debug)]
pub enum RemoteError {
    Transport(std::io::Error),
    InvalidResponse(serde_json::Error),
    Http { status: u16, message: String },
    Protocol { context: &'static str },
}

impl RemoteError {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Transport(_) => "transport",
            Self::InvalidResponse(_) => "invalid_response",
            Self::Http { .. } => "http",
            Self::Protocol { .. } => "protocol",
        }
    }

    pub const fn is_not_found(&self) -> bool {
        matches!(self, Self::Http { status: 404, .. })
    }
}

impl fmt::Display for RemoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(source) => write!(formatter, "transport error: {source}"),
            Self::InvalidResponse(source) => write!(formatter, "invalid response: {source}"),
            Self::Http { status, message } => {
                write!(formatter, "HTTP status {status}: {message}")
            }
            Self::Protocol { context } => write!(formatter, "protocol failure: {context}"),
        }
    }
}

impl std::error::Error for RemoteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(source) => Some(source),
            Self::InvalidResponse(source) => Some(source),
            Self::Http { .. } | Self::Protocol { .. } => None,
        }
    }
}

pub trait RevokeTokenClient {
    fn delete_token(
        &self,
        client_id: &str,
        client_secret: &str,
        access_token: &str,
    ) -> Result<(), RemoteError>;
}
