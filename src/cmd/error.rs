use crate::cache::CacheError;
use crate::config::ConfigError;
use crate::git::GitError;
use crate::github::GitHubError;
use std::fmt;

#[derive(Debug)]
pub enum CmdError {
    Config(ConfigError),
    Cache(CacheError),
    Git(GitError),
    GitHub(GitHubError),
    ProfileNotFound(String),
    ProfileRequired,
    DerivedLoginNotAllowed {
        profile: String,
        source: String,
    },
    SourceProfileNotRoot {
        profile: String,
        source: String,
    },
    ClientSecretRequired {
        profile: String,
    },
    NoRootTokenCached {
        profile: String,
    },
    NoSourceTokenCached {
        profile: String,
    },
    InvalidOutputFormat(String),
    InvalidRepositoryScope {
        value: String,
        reason: &'static str,
    },
    RepositoryOwnerMismatch {
        repository: String,
        account: String,
    },
    RootScopeRejected {
        profile: String,
    },
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
    RootGenerationChanged {
        profile: String,
    },
    InvalidLifetime {
        token_kind: &'static str,
        reason: String,
    },
    OAuthExpired,
    OAuthAccessDenied,
    RevocationFailed {
        context: Box<Self>,
        source: GitHubError,
    },
    ClearIncomplete {
        failures: usize,
    },
    Io(std::io::Error),
}

impl fmt::Display for CmdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(err) => write!(f, "configuration error: {err}"),
            Self::Cache(err) => write!(f, "cache error: {err}"),
            Self::Git(err) => write!(f, "git error: {err}"),
            Self::GitHub(err) => write!(f, "github error: {err}"),
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
            Self::SourceProfileNotRoot { profile, source } => write!(
                f,
                "derived profile '{profile}' references non-root source profile '{source}'"
            ),
            Self::ClientSecretRequired { profile } => write!(
                f,
                "root profile '{profile}' has no client secret; derived token minting is unavailable"
            ),
            Self::NoRootTokenCached { profile } => write!(
                f,
                "No valid cached token found for root profile '{profile}'. Please log in first: ghst login -p {profile}"
            ),
            Self::NoSourceTokenCached { profile } => write!(
                f,
                "No valid cached token found for root source profile '{profile}'. Please log in to the root profile first: ghst login -p {profile}"
            ),
            Self::InvalidOutputFormat(value) => write!(
                f,
                "invalid output format '{value}', expected 'text', 'json', or 'env'"
            ),
            Self::InvalidRepositoryScope { value, reason } => {
                write!(f, "invalid repository scope '{value}': {reason}")
            }
            Self::RepositoryOwnerMismatch {
                repository,
                account,
            } => write!(
                f,
                "repository '{repository}' is not owned by configured target account '{account}'"
            ),
            Self::RootScopeRejected { profile } => write!(
                f,
                "root profile '{profile}' cannot be repository-scoped; omit --repo to return its raw root token"
            ),
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
            Self::StaleProvenance { profile, reason } => {
                write!(
                    f,
                    "cached token for profile '{profile}' has stale provenance: {reason}"
                )
            }
            Self::RootGenerationChanged { profile } => write!(
                f,
                "root token for profile '{profile}' changed while minting; retry the token request"
            ),
            Self::InvalidLifetime { token_kind, reason } => {
                write!(f, "invalid {token_kind} token lifetime: {reason}")
            }
            Self::OAuthExpired => {
                write!(f, "device code expired; run `ghst login` again")
            }
            Self::OAuthAccessDenied => write!(f, "authorization request was denied by the user"),
            Self::RevocationFailed { context, source } => {
                write!(
                    f,
                    "{context}; additionally failed to revoke the unused token: {source}"
                )
            }
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
            Self::Io(err) => Some(err),
            Self::RevocationFailed { source, .. } => Some(source),
            Self::ProfileNotFound(_)
            | Self::ProfileRequired
            | Self::DerivedLoginNotAllowed { .. }
            | Self::SourceProfileNotRoot { .. }
            | Self::ClientSecretRequired { .. }
            | Self::NoRootTokenCached { .. }
            | Self::NoSourceTokenCached { .. }
            | Self::InvalidOutputFormat(_)
            | Self::InvalidRepositoryScope { .. }
            | Self::RepositoryOwnerMismatch { .. }
            | Self::RootScopeRejected { .. }
            | Self::UnexpectedCacheKind { .. }
            | Self::InconsistentCacheMetadata { .. }
            | Self::StaleProvenance { .. }
            | Self::RootGenerationChanged { .. }
            | Self::InvalidLifetime { .. }
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
