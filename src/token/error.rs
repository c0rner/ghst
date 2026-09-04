use crate::repository::RepositoryError;
use crate::token::RemoteError;
use std::fmt;

#[derive(Debug)]
pub enum TokenError {
    Cache(crate::cache::CacheError),
    GitHub(RemoteError),
    ScopedTokenForbidden {
        profile: String,
        source_profile: String,
        source: RemoteError,
    },
    Repository(RepositoryError),
    NoBaseTokenCached(String),
    NoSourceBaseTokenCached(String),
    AppScopeRejected(String),
    RunRequiresScoped(String),
    Random(getrandom::Error),
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
    BaseGenerationChanged(String),
    RenewalPersisted(String),
    InvalidLifetime {
        token_kind: &'static str,
        reason: String,
    },
    RevocationFailed {
        context: Box<Self>,
        source: RemoteError,
    },
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cache(error) => write!(f, "cache error: {error}"),
            Self::GitHub(error) => write!(f, "github error: {error}"),
            Self::ScopedTokenForbidden {
                profile,
                source_profile,
                source,
            } => write!(
                f,
                "github rejected the scoped token request for scoped profile '{profile}': {source}. The requested permissions or repository access likely exceed the GitHub App installation for source app profile '{source_profile}'; check the App installation in GitHub settings and the scoped profile's `permissions` and `repo` in profiles.toml"
            ),
            Self::Repository(error) => write!(f, "{error}"),
            Self::NoBaseTokenCached(profile) => {
                write!(f, "no valid base token cached for app profile '{profile}'")
            }
            Self::NoSourceBaseTokenCached(profile) => {
                write!(
                    f,
                    "no valid base token cached for source app profile '{profile}'"
                )
            }
            Self::AppScopeRejected(profile) => {
                write!(f, "app profile '{profile}' cannot be repository-scoped")
            }
            Self::RunRequiresScoped(profile) => {
                write!(
                    f,
                    "profile '{profile}' is an app profile; run requires a scoped profile"
                )
            }
            Self::Random(error) => write!(f, "operating-system randomness unavailable: {error}"),
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
            Self::BaseGenerationChanged(profile) => write!(
                f,
                "base token for profile '{profile}' changed while minting; retry the token request"
            ),
            Self::RenewalPersisted(profile) => write!(
                f,
                "renewed token for profile '{profile}' was persisted before displaced-token cleanup"
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
            Self::Random(error) => Some(error),
            Self::ScopedTokenForbidden { source, .. } | Self::RevocationFailed { source, .. } => {
                Some(source)
            }
            _ => None,
        }
    }
}

impl From<crate::cache::CacheError> for TokenError {
    fn from(error: crate::cache::CacheError) -> Self {
        Self::Cache(error)
    }
}

impl From<RemoteError> for TokenError {
    fn from(error: RemoteError) -> Self {
        Self::GitHub(error)
    }
}

impl From<RepositoryError> for TokenError {
    fn from(error: RepositoryError) -> Self {
        Self::Repository(error)
    }
}

impl From<getrandom::Error> for TokenError {
    fn from(error: getrandom::Error) -> Self {
        Self::Random(error)
    }
}

#[cfg(test)]
mod error_tests {
    use super::TokenError;

    #[test]
    fn domain_errors_do_not_name_cli_commands_or_options() {
        for error in [
            TokenError::NoBaseTokenCached("developer".into()),
            TokenError::NoSourceBaseTokenCached("developer".into()),
            TokenError::AppScopeRejected("developer".into()),
        ] {
            let message = error.to_string();
            assert!(!message.contains("ghst"));
            assert!(!message.contains("--repo"));
        }
    }

    #[test]
    fn random_error_exposes_its_source() {
        let random = getrandom::Error::UNSUPPORTED;
        let error = TokenError::from(random);

        let source = std::error::Error::source(&error).expect("random error should have a source");
        assert_eq!(source.downcast_ref::<getrandom::Error>(), Some(&random));
    }
}
