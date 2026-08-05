use crate::github::GitHubError;
use crate::repository::RepositoryError;
use std::fmt;

#[derive(Debug)]
pub enum TokenError {
    Cache(crate::cache::CacheError),
    GitHub(GitHubError),
    Repository(RepositoryError),
    ProfileNotFound(String),
    SourceProfileNotRoot {
        profile: String,
        source: String,
    },
    ClientSecretRequired(String),
    NoRootTokenCached(String),
    NoSourceTokenCached(String),
    RootScopeRejected(String),
    UnexpectedCacheKind {
        profile: String,
        expected: &'static str,
        actual: &'static str,
    },
    InconsistentCacheMetadata {
        profile: String,
        found: String,
    },
    StaleProvenance {
        profile: String,
        reason: &'static str,
    },
    RootGenerationChanged(String),
    InvalidLifetime {
        token_kind: &'static str,
        reason: String,
    },
    RevocationFailed {
        context: Box<Self>,
        source: GitHubError,
    },
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cache(error) => write!(f, "cache error: {error}"),
            Self::GitHub(error) => write!(f, "github error: {error}"),
            Self::Repository(error) => write!(f, "{error}"),
            Self::ProfileNotFound(profile) => {
                write!(f, "profile '{profile}' is not defined in configuration")
            }
            Self::SourceProfileNotRoot { profile, source } => write!(
                f,
                "derived profile '{profile}' references non-root source profile '{source}'"
            ),
            Self::ClientSecretRequired(profile) => write!(
                f,
                "root profile '{profile}' has no client secret; derived token minting is unavailable"
            ),
            Self::NoRootTokenCached(profile) => {
                write!(f, "no valid token cached for root profile '{profile}'")
            }
            Self::NoSourceTokenCached(profile) => {
                write!(
                    f,
                    "no valid token cached for root source profile '{profile}'"
                )
            }
            Self::RootScopeRejected(profile) => {
                write!(f, "root profile '{profile}' cannot be repository-scoped")
            }
            Self::UnexpectedCacheKind {
                profile,
                expected,
                actual,
            } => write!(
                f,
                "cache entry for profile '{profile}' has kind '{actual}', expected '{expected}'"
            ),
            Self::InconsistentCacheMetadata { profile, found } => write!(
                f,
                "cache entry for profile '{profile}' contains inconsistent profile metadata '{found}'"
            ),
            Self::StaleProvenance { profile, reason } => write!(
                f,
                "cached token for profile '{profile}' has stale provenance: {reason}"
            ),
            Self::RootGenerationChanged(profile) => write!(
                f,
                "root token for profile '{profile}' changed while minting; retry the token request"
            ),
            Self::InvalidLifetime { token_kind, reason } => {
                write!(f, "invalid {token_kind} token lifetime: {reason}")
            }
            Self::RevocationFailed { context, source } => write!(
                f,
                "{context}; additionally failed to revoke the unused token: {source}"
            ),
        }
    }
}

impl std::error::Error for TokenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cache(error) => Some(error),
            Self::GitHub(error) => Some(error),
            Self::Repository(error) => Some(error),
            Self::RevocationFailed { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<crate::cache::CacheError> for TokenError {
    fn from(error: crate::cache::CacheError) -> Self {
        Self::Cache(error)
    }
}

impl From<GitHubError> for TokenError {
    fn from(error: GitHubError) -> Self {
        Self::GitHub(error)
    }
}

impl From<RepositoryError> for TokenError {
    fn from(error: RepositoryError) -> Self {
        Self::Repository(error)
    }
}

#[cfg(test)]
mod error_tests {
    use super::TokenError;

    #[test]
    fn domain_errors_do_not_name_cli_commands_or_options() {
        for error in [
            TokenError::NoRootTokenCached("developer".into()),
            TokenError::NoSourceTokenCached("developer".into()),
            TokenError::RootScopeRejected("developer".into()),
        ] {
            let message = error.to_string();
            assert!(!message.contains("ghst"));
            assert!(!message.contains("--repo"));
        }
    }
}
