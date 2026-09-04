pub mod edit;
pub mod error;
pub mod login;
pub mod profiles;
pub mod prune;
pub mod revoke;
pub mod run;
pub mod status;
pub mod token;

use crate::config::Config;
use argh::FromArgs;
pub use error::CmdError;
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::str::FromStr;
use time::{UtcOffset, error::IndeterminateOffset};

use crate::cache::format_rfc3339;
use crate::domain::credential::TokenExpiry;

pub const GHST_VERSION: &str = env!("CARGO_PKG_VERSION");

fn format_human_expiry(expiry: TokenExpiry) -> String {
    format_human_expiry_with_offset(expiry, UtcOffset::local_offset_at(expiry.value()))
}

fn format_human_expiry_with_offset(
    expiry: TokenExpiry,
    offset: Result<UtcOffset, IndeterminateOffset>,
) -> String {
    let offset = offset.unwrap_or_else(|error| {
        tracing::debug!(%error, "could not determine local UTC offset; displaying expiry in UTC");
        UtcOffset::UTC
    });
    format_rfc3339(expiry.value().to_offset(offset))
}

/// `GhstCli` command line interface
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(
    description = "\
'{command_name}' is a local, developer-focused CLI tool that issues short-lived \
GitHub App user access tokens for humans and AI coding tools.\n\
It replaces long-lived personal access credentials with user-attributed, \
strictly scoped access tokens protecting a trusted human operator's GitHub \
authority from less-trusted processes running on the same machine.\n\
It does not attempt to prevent the operator themselves from bypassing local \
profiles or directly invoking the GitHub API.",
    example = "\
{command_name} edit --init
{command_name} login --profile developer
{command_name} token --profile reader --repo acme/api --format env
{command_name} run --profile contributor --repo auto -- llm_tool",
    note = "Version: {GHST_VERSION}"
)]
pub struct GhstCli {
    /// optional path to configuration file (override `GHST_CONFIG` or ~/.config/ghst/profiles.toml)
    #[argh(option, short = 'c')]
    pub config: Option<PathBuf>,

    /// display version information
    #[argh(switch)]
    pub version: bool,

    #[argh(subcommand)]
    pub command: SubCommand,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand)]
pub enum SubCommand {
    Edit(EditCmd),
    Login(LoginCmd),
    Token(TokenCmd),
    Status(StatusCmd),
    Profiles(ProfilesCmd),
    Revoke(RevokeCmd),
    Prune(PruneCmd),
    Run(RunCmd),
}

impl SubCommand {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Edit(_) => "edit",
            Self::Login(_) => "login",
            Self::Token(_) => "token",
            Self::Status(_) => "status",
            Self::Profiles(_) => "profiles",
            Self::Revoke(_) => "revoke",
            Self::Prune(_) => "prune",
            Self::Run(_) => "run",
        }
    }
}

/// Open and validate the active configuration in your preferred editor.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "edit")]
pub struct EditCmd {
    /// create a starter configuration when none exists
    #[argh(switch)]
    pub init: bool,
}

/// Authenticate a profile via GitHub App OAuth Device Flow.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "login")]
pub struct LoginCmd {
    /// target profile name (override `GHST_PROFILE`)
    #[argh(option, short = 'p')]
    pub profile: Option<String>,

    /// do not attempt to open browser automatically
    #[argh(switch)]
    pub no_browser: bool,
}

/// Mint or retrieve a scoped GitHub token.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "token")]
pub struct TokenCmd {
    /// target profile name (override `GHST_PROFILE`)
    #[argh(option, short = 'p')]
    pub profile: Option<String>,

    /// scoped-profile repository selection (all, auto, or owner/repo; repeat to select repositories; rejected for app profiles)
    #[argh(option, short = 'r')]
    pub repo: Vec<String>,

    /// output format (text, json, or env)
    #[argh(option, short = 'f', default = "OutputFormat::Text")]
    pub format: OutputFormat,
}

/// Display cached token status.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "status")]
pub struct StatusCmd {}

/// List configured permission profiles.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "profiles")]
pub struct ProfilesCmd {
    /// show detailed profile information
    #[argh(switch, short = 'v')]
    pub verbose: bool,
}

/// Revoke one cached credential by ID, or every cached credential with --all.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "revoke")]
pub struct RevokeCmd {
    /// cache slot ID reported by `ghst status`
    #[argh(positional)]
    pub id: Option<String>,

    /// required acknowledgement that every cached credential will be revoked
    #[argh(switch)]
    pub all: bool,
}

/// Remove expired entries and revoke tokens from abandoned runs.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "prune")]
pub struct PruneCmd {}

/// Run a command with a fresh scoped GitHub token. Access that dies with the process.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "run")]
pub struct RunCmd {
    /// target scoped profile name (override `GHST_PROFILE`)
    #[argh(option, short = 'p')]
    pub profile: Option<String>,

    /// scoped-profile repository selection (all, auto, or owner/repo; repeat to select repositories)
    #[argh(option, short = 'r')]
    pub repo: Vec<String>,

    /// command and arguments to execute (precede with --)
    #[argh(positional, greedy)]
    pub command: Vec<OsString>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Env,
}

impl FromStr for OutputFormat {
    type Err = CmdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "env" => Ok(Self::Env),
            other => Err(CmdError::InvalidOutputFormat(other.to_string())),
        }
    }
}

fn resolve_profile_name(cli_profile: Option<&str>, config: &Config) -> Result<String, CmdError> {
    if let Some(profile) = cli_profile {
        tracing::debug!(profile, source = "command_line", "resolved profile");
        return Ok(profile.to_owned());
    }
    if let Ok(profile) = env::var("GHST_PROFILE") {
        let profile = profile.trim();
        if !profile.is_empty() {
            tracing::debug!(profile, source = "environment", "resolved profile");
            return Ok(profile.to_owned());
        }
    }
    let profile = config
        .default_profile
        .clone()
        .ok_or(CmdError::ProfileRequired)?;
    tracing::debug!(
        profile,
        source = "configuration_default",
        "resolved profile"
    );
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_expiry_uses_local_offset_with_utc_fallback() {
        let expiry =
            TokenExpiry::new(time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap());
        let local = UtcOffset::from_hms(5, 30, 0).unwrap();

        assert_eq!(
            format_human_expiry_with_offset(expiry, Ok(local)),
            "2023-11-15T03:43:20+05:30"
        );
        assert_eq!(
            format_human_expiry_with_offset(expiry, Err(IndeterminateOffset)),
            "2023-11-14T22:13:20Z"
        );
    }

    #[test]
    fn test_login_cmd_parsing() {
        let args = GhstCli::from_args(&["ghst"], &["login", "--profile", "developer"]).unwrap();
        assert_eq!(
            args,
            GhstCli {
                config: None,
                version: false,
                command: SubCommand::Login(LoginCmd {
                    profile: Some("developer".to_string()),
                    no_browser: false,
                })
            }
        );
    }

    #[test]
    fn test_login_cmd_no_browser_parsing() {
        let args = GhstCli::from_args(
            &["ghst"],
            &["login", "--profile", "developer", "--no-browser"],
        )
        .unwrap();
        assert_eq!(
            args,
            GhstCli {
                config: None,
                version: false,
                command: SubCommand::Login(LoginCmd {
                    profile: Some("developer".to_string()),
                    no_browser: true,
                })
            }
        );
    }

    #[test]
    fn test_token_cmd_multiple_repos_and_format() {
        let args = GhstCli::from_args(
            &["ghst"],
            &[
                "token",
                "--profile",
                "reader",
                "--repo",
                "octo-org/repo1",
                "--repo",
                "octo-org/repo2",
                "--format",
                "env",
            ],
        )
        .unwrap();
        assert_eq!(
            args,
            GhstCli {
                config: None,
                version: false,
                command: SubCommand::Token(TokenCmd {
                    profile: Some("reader".to_string()),
                    repo: vec!["octo-org/repo1".to_string(), "octo-org/repo2".to_string()],
                    format: OutputFormat::Env,
                })
            }
        );
    }

    #[test]
    fn generated_help_uses_app_and_scoped_profile_terminology() {
        let top_level_help = GhstCli::from_args(&["ghst"], &["--help"]).unwrap_err();
        assert!(
            top_level_help
                .output
                .contains(&format!("Version: {GHST_VERSION}"))
        );
        assert!(top_level_help.output.contains("--version"));

        let token_help = GhstCli::from_args(&["ghst"], &["token", "--help"]).unwrap_err();
        let token_help = token_help
            .output
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(token_help.contains("Mint or retrieve a scoped GitHub token"));
        assert!(token_help.contains("rejected for app profiles"));

        let run_help = GhstCli::from_args(&["ghst"], &["run", "--help"]).unwrap_err();
        let run_help = run_help
            .output
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(run_help.contains("target scoped profile name"));
        assert!(run_help.contains("scoped-profile repository selection"));
    }

    #[test]
    fn test_run_cmd_parsing_preserves_command_arguments() {
        let args = GhstCli::from_args(
            &["ghst"],
            &[
                "run",
                "--profile",
                "reader",
                "--repo",
                "acme/api",
                "--",
                "printf",
                "%s",
                "a b",
            ],
        )
        .unwrap();
        assert_eq!(
            args,
            GhstCli {
                config: None,
                version: false,
                command: SubCommand::Run(RunCmd {
                    profile: Some("reader".to_string()),
                    repo: vec!["acme/api".to_string()],
                    command: vec!["printf".into(), "%s".into(), "a b".into()],
                })
            }
        );
    }

    #[test]
    fn test_maintenance_commands() {
        let id = "0123456";
        assert!(matches!(
            GhstCli::from_args(&["ghst"], &["prune"]).unwrap().command,
            SubCommand::Prune(PruneCmd {})
        ));
        assert_eq!(
            GhstCli::from_args(&["ghst"], &["revoke", "--all"])
                .unwrap()
                .command,
            SubCommand::Revoke(RevokeCmd {
                id: None,
                all: true,
            })
        );
        assert_eq!(
            GhstCli::from_args(&["ghst"], &["revoke", id])
                .unwrap()
                .command,
            SubCommand::Revoke(RevokeCmd {
                id: Some(id.into()),
                all: false,
            })
        );
    }

    #[test]
    fn test_edit_cmd_parsing() {
        assert_eq!(
            GhstCli::from_args(&["ghst"], &["edit"]).unwrap(),
            GhstCli {
                config: None,
                version: false,
                command: SubCommand::Edit(EditCmd { init: false }),
            }
        );
        assert_eq!(
            GhstCli::from_args(&["ghst"], &["edit", "--init"]).unwrap(),
            GhstCli {
                config: None,
                version: false,
                command: SubCommand::Edit(EditCmd { init: true }),
            }
        );
    }

    #[test]
    fn test_profiles_cmd_parsing() {
        let args = GhstCli::from_args(&["ghst"], &["profiles"]).unwrap();
        assert_eq!(
            args,
            GhstCli {
                config: None,
                version: false,
                command: SubCommand::Profiles(ProfilesCmd { verbose: false }),
            }
        );

        let args_v = GhstCli::from_args(&["ghst"], &["profiles", "-v"]).unwrap();
        assert_eq!(
            args_v,
            GhstCli {
                config: None,
                version: false,
                command: SubCommand::Profiles(ProfilesCmd { verbose: true }),
            }
        );
    }

    #[test]
    fn test_output_format_from_str() {
        assert_eq!("text".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
        assert_eq!("JSON".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!("Env".parse::<OutputFormat>().unwrap(), OutputFormat::Env);
        assert!("invalid".parse::<OutputFormat>().is_err());
    }
}
