use crate::cache::CacheError;
use crate::config::ConfigError;
use crate::github::GitHubError;
use crate::token::TokenError;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum CmdError {
    Config(ConfigError),
    Cache(CacheError),
    GitHub(GitHubError),
    Token(TokenError),
    ConfigNotFound(PathBuf),
    NoEditorFound,
    InvalidEditorCommand {
        variable: &'static str,
    },
    EditorLaunch {
        editor: String,
        source: std::io::Error,
    },
    EditorFailed {
        editor: String,
        code: Option<i32>,
    },
    ProfileNotFound(String),
    ProfileRequired,
    ScopedLoginNotAllowed {
        profile: String,
        source: String,
    },
    InvalidOutputFormat(String),
    OAuthExpired,
    OAuthAccessDenied,
    PruneIncomplete {
        failures: usize,
    },
    RevokeSelectionRequired,
    RevokeSelectionConflict,
    InvalidRevokeId,
    RevokeTargetNotFound(String),
    RevokeTargetAmbiguous(String),
    RevokeIncomplete {
        failures: usize,
    },
    MissingRunCommand,
    Io(std::io::Error),
}

impl fmt::Display for CmdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(err) => write!(f, "configuration error: {err}"),
            Self::Cache(err) => write!(f, "cache error: {err}"),
            Self::GitHub(err) => write!(f, "github error: {err}"),
            Self::Token(TokenError::NoBaseTokenCached(profile)) => write!(
                f,
                "No valid base token found for app profile '{profile}'. Please log in first: ghst login -p {profile}"
            ),
            Self::Token(TokenError::NoSourceBaseTokenCached(profile)) => write!(
                f,
                "No valid base token found for source app profile '{profile}'. Please log in to the app profile first: ghst login -p {profile}"
            ),
            Self::Token(TokenError::AppScopeRejected(profile)) => write!(
                f,
                "app profile '{profile}' cannot be repository-scoped; omit --repo to return its raw base token"
            ),
            Self::Token(err) => err.fmt(f),
            Self::ConfigNotFound(path) => write!(
                f,
                "configuration not found at {}. Run 'ghst edit --init' to create a starter configuration.",
                path.display()
            ),
            Self::NoEditorFound => write!(
                f,
                "no editor found; set VISUAL or EDITOR, or install nano, vim, or vi"
            ),
            Self::InvalidEditorCommand { variable } => {
                write!(f, "{variable} contains an invalid editor command")
            }
            Self::EditorLaunch { editor, source } => {
                write!(f, "failed to launch editor '{editor}': {source}")
            }
            Self::EditorFailed { editor, code } => match code {
                Some(code) => write!(f, "editor '{editor}' exited with status {code}"),
                None => write!(f, "editor '{editor}' was terminated by a signal"),
            },
            Self::ProfileNotFound(profile) => {
                write!(f, "profile '{profile}' is not defined in configuration")
            }
            Self::ProfileRequired => write!(
                f,
                "no profile specified; pass `-p <profile>`, set `GHST_PROFILE`, or configure `default_profile`"
            ),
            Self::ScopedLoginNotAllowed { profile, source } => write!(
                f,
                "profile '{profile}' is scoped; log in to its source app profile instead: ghst login -p {source}"
            ),
            Self::InvalidOutputFormat(value) => write!(
                f,
                "invalid output format '{value}', expected 'text', 'json', or 'env'"
            ),
            Self::OAuthExpired => {
                write!(f, "device code expired; run `ghst login` again")
            }
            Self::OAuthAccessDenied => write!(f, "authorization request was denied by the user"),
            Self::PruneIncomplete { failures } => {
                write!(f, "cache pruning was incomplete ({failures} failure(s))")
            }
            Self::RevokeSelectionRequired => write!(
                f,
                "revoke requires a cache slot ID from `ghst status` or `--all`"
            ),
            Self::RevokeSelectionConflict => {
                write!(
                    f,
                    "revoke accepts either a cache slot ID or `--all`, not both"
                )
            }
            Self::InvalidRevokeId => {
                write!(f, "invalid cache slot ID; copy an ID from `ghst status`")
            }
            Self::RevokeTargetNotFound(id) => {
                write!(f, "no cached credential found for ID '{id}'")
            }
            Self::RevokeTargetAmbiguous(id) => write!(
                f,
                "cache slot ID '{id}' is ambiguous; run `ghst status` and use the longer ID shown"
            ),
            Self::RevokeIncomplete { failures } => {
                write!(
                    f,
                    "credential revocation was incomplete ({failures} failure(s))"
                )
            }
            Self::MissingRunCommand => write!(f, "run requires a command after `--`"),
            Self::Io(err) => write!(f, "IO error: {err}"),
        }
    }
}

impl std::error::Error for CmdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(err) => Some(err),
            Self::Cache(err) => Some(err),
            Self::GitHub(err) => Some(err),
            Self::Token(err) => Some(err),
            Self::EditorLaunch { source, .. } => Some(source),
            Self::Io(err) => Some(err),
            Self::ConfigNotFound(_)
            | Self::NoEditorFound
            | Self::InvalidEditorCommand { .. }
            | Self::EditorFailed { .. }
            | Self::ProfileNotFound(_)
            | Self::ProfileRequired
            | Self::ScopedLoginNotAllowed { .. }
            | Self::InvalidOutputFormat(_)
            | Self::OAuthExpired
            | Self::OAuthAccessDenied
            | Self::PruneIncomplete { .. }
            | Self::RevokeSelectionRequired
            | Self::RevokeSelectionConflict
            | Self::InvalidRevokeId
            | Self::RevokeTargetNotFound(_)
            | Self::RevokeTargetAmbiguous(_)
            | Self::RevokeIncomplete { .. }
            | Self::MissingRunCommand => None,
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
            CmdError::Token(TokenError::NoBaseTokenCached("developer".into())).to_string(),
            "No valid base token found for app profile 'developer'. Please log in first: ghst login -p developer"
        );
        assert_eq!(
            CmdError::Token(TokenError::NoSourceBaseTokenCached("developer".into())).to_string(),
            "No valid base token found for source app profile 'developer'. Please log in to the app profile first: ghst login -p developer"
        );
        assert_eq!(
            CmdError::Token(TokenError::AppScopeRejected("developer".into())).to_string(),
            "app profile 'developer' cannot be repository-scoped; omit --repo to return its raw base token"
        );
        assert_eq!(
            CmdError::ScopedLoginNotAllowed {
                profile: "reader".into(),
                source: "developer".into(),
            }
            .to_string(),
            "profile 'reader' is scoped; log in to its source app profile instead: ghst login -p developer"
        );
        assert_eq!(
            CmdError::Token(TokenError::RunRequiresScoped("developer".into())).to_string(),
            "profile 'developer' is an app profile; run requires a scoped profile"
        );
    }

    #[test]
    fn missing_configuration_has_initialization_guidance() {
        let error = CmdError::ConfigNotFound("/tmp/ghst/profiles.toml".into()).to_string();
        assert!(error.contains("/tmp/ghst/profiles.toml"));
        assert!(error.contains("ghst edit --init"));
    }
}
