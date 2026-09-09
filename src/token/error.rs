use crate::token::RemoteError;
use std::fmt;

#[derive(Debug)]
pub enum TokenError<E = crate::cache::CacheError> {
    Storage(E),
    GitHub(RemoteError),
    ScopedTokenForbidden {
        profile: String,
        source_profile: String,
        source: RemoteError,
    },
    NoBaseTokenCached(String),
    NoSourceBaseTokenCached(String),
    Random(getrandom::Error),
    InconsistentCacheMetadata {
        profile: String,
        found: String,
    },
    StaleProvenance {
        profile: String,
        reason: &'static str,
    },
    BaseGenerationChanged(String),
    EpochChanged(String),
    RenewalEntryChanged(String),
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

impl<E: fmt::Display> fmt::Display for TokenError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "storage error: {error}"),
            Self::GitHub(error) => write!(f, "github error: {error}"),
            Self::ScopedTokenForbidden {
                profile,
                source_profile,
                source,
            } => write!(
                f,
                "github rejected the scoped token request for scoped profile '{profile}': {source}. The requested permissions or repository access likely exceed the GitHub App installation for source app profile '{source_profile}'; check the App installation in GitHub settings and the scoped profile's `permissions` and `repo` in profiles.toml"
            ),
            Self::NoBaseTokenCached(profile) => {
                write!(f, "no valid base token cached for app profile '{profile}'")
            }
            Self::NoSourceBaseTokenCached(profile) => {
                write!(
                    f,
                    "no valid base token cached for source app profile '{profile}'"
                )
            }
            Self::Random(error) => write!(f, "operating-system randomness unavailable: {error}"),
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
            Self::EpochChanged(profile) => write!(
                f,
                "cache epoch changed while issuing token for profile '{profile}'; retry the token request"
            ),
            Self::RenewalEntryChanged(profile) => write!(
                f,
                "cached scoped token for profile '{profile}' changed while renewing; retry the token request"
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

impl<E: std::error::Error + 'static> std::error::Error for TokenError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            Self::GitHub(error) => Some(error),
            Self::Random(error) => Some(error),
            Self::ScopedTokenForbidden { source, .. } | Self::RevocationFailed { source, .. } => {
                Some(source)
            }
            _ => None,
        }
    }
}

impl From<crate::cache::CacheError> for TokenError<crate::cache::CacheError> {
    fn from(error: crate::cache::CacheError) -> Self {
        Self::Storage(error)
    }
}

impl<E> From<RemoteError> for TokenError<E> {
    fn from(error: RemoteError) -> Self {
        Self::GitHub(error)
    }
}

impl<E> From<getrandom::Error> for TokenError<E> {
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
            TokenError::<crate::cache::CacheError>::NoBaseTokenCached("developer".into()),
            TokenError::<crate::cache::CacheError>::NoSourceBaseTokenCached("developer".into()),
        ] {
            let message = error.to_string();
            assert!(!message.contains("ghst"));
            assert!(!message.contains("--repo"));
        }
    }

    #[test]
    fn random_error_exposes_its_source() {
        let random = getrandom::Error::UNSUPPORTED;
        let error: TokenError = TokenError::from(random);

        let source = std::error::Error::source(&error).expect("random error should have a source");
        assert_eq!(source.downcast_ref::<getrandom::Error>(), Some(&random));
    }
}
