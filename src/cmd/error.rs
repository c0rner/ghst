use crate::cache::CacheError;
use crate::config::ConfigError;
use crate::git::GitError;
use crate::github::GitHubError;
use crate::token::TokenError;
use std::fmt;

#[derive(Debug)]
pub enum CmdError {
    Config(ConfigError),
    Cache(CacheError),
    Git(GitError),
    GitHub(GitHubError),
    Token(TokenError),
    ProfileNotFound(String),
    ProfileRequired,
    DerivedLoginNotAllowed { profile: String, source: String },
    InvalidOutputFormat(String),
    OAuthExpired,
    OAuthAccessDenied,
    ClearIncomplete { failures: usize },
    Io(std::io::Error),
}

impl fmt::Display for CmdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(err) => write!(f, "configuration error: {err}"),
            Self::Cache(err) => write!(f, "cache error: {err}"),
            Self::Git(err) => write!(f, "git error: {err}"),
            Self::GitHub(err) => write!(f, "github error: {err}"),
            Self::Token(TokenError::NoRootTokenCached(profile)) => write!(
                f,
                "No valid cached token found for root profile '{profile}'. Please log in first: ghst login -p {profile}"
            ),
            Self::Token(TokenError::NoSourceTokenCached(profile)) => write!(
                f,
                "No valid cached token found for root source profile '{profile}'. Please log in to the root profile first: ghst login -p {profile}"
            ),
            Self::Token(TokenError::RootScopeRejected(profile)) => write!(
                f,
                "root profile '{profile}' cannot be repository-scoped; omit --repo to return its raw root token"
            ),
            Self::Token(err) => err.fmt(f),
            Self::ProfileNotFound(profile) => {
                write!(f, "profile '{profile}' is not defined in configuration")
            }
            Self::ProfileRequired => write!(
                f,
                "no profile specified; pass `-p <profile>`, set `GHST_PROFILE`, or configure `default_profile`"
            ),
            Self::DerivedLoginNotAllowed { profile, source } => write!(
                f,
                "profile '{profile}' is derived; log in to its root source instead: ghst login -p {source}"
            ),
            Self::InvalidOutputFormat(value) => write!(
                f,
                "invalid output format '{value}', expected 'text', 'json', or 'env'"
            ),
            Self::OAuthExpired => {
                write!(f, "device code expired; run `ghst login` again")
            }
            Self::OAuthAccessDenied => write!(f, "authorization request was denied by the user"),
            Self::ClearIncomplete { failures } => {
                write!(f, "cache cleanup was incomplete ({failures} failure(s))")
            }
            Self::Io(err) => write!(f, "IO error: {err}"),
        }
    }
}

impl std::error::Error for CmdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(err) => Some(err),
            Self::Cache(err) => Some(err),
            Self::Git(err) => Some(err),
            Self::GitHub(err) => Some(err),
            Self::Token(err) => Some(err),
            Self::Io(err) => Some(err),
            Self::ProfileNotFound(_)
            | Self::ProfileRequired
            | Self::DerivedLoginNotAllowed { .. }
            | Self::InvalidOutputFormat(_)
            | Self::OAuthExpired
            | Self::OAuthAccessDenied
            | Self::ClearIncomplete { .. } => None,
        }
    }
}

impl From<ConfigError> for CmdError {
    fn from(err: ConfigError) -> Self {
        Self::Config(err)
    }
}

impl From<CacheError> for CmdError {
    fn from(err: CacheError) -> Self {
        Self::Cache(err)
    }
}

impl From<GitError> for CmdError {
    fn from(err: GitError) -> Self {
        Self::Git(err)
    }
}

impl From<TokenError> for CmdError {
    fn from(error: TokenError) -> Self {
        Self::Token(error)
    }
}

impl From<GitHubError> for CmdError {
    fn from(err: GitHubError) -> Self {
        Self::GitHub(err)
    }
}

impl From<std::io::Error> for CmdError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_errors_gain_cli_specific_guidance() {
        assert_eq!(
            CmdError::Token(TokenError::NoRootTokenCached("developer".into())).to_string(),
            "No valid cached token found for root profile 'developer'. Please log in first: ghst login -p developer"
        );
        assert_eq!(
            CmdError::Token(TokenError::NoSourceTokenCached("developer".into())).to_string(),
            "No valid cached token found for root source profile 'developer'. Please log in to the root profile first: ghst login -p developer"
        );
        assert_eq!(
            CmdError::Token(TokenError::RootScopeRejected("developer".into())).to_string(),
            "root profile 'developer' cannot be repository-scoped; omit --repo to return its raw root token"
        );
    }
}
