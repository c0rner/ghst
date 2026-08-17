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
{command_name} login --profile developer
{command_name} token --profile reader --repo acme/api --format env
{command_name} run --profile contributor --repo auto -- llm_tool"
)]
pub struct GhstCli {
    /// optional path to configuration file (override `GHST_CONFIG` or ~/.config/ghst/profiles.toml)
    #[argh(option, short = 'c')]
    pub config: Option<PathBuf>,

    #[argh(subcommand)]
    pub command: SubCommand,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand)]
pub enum SubCommand {
    Login(LoginCmd),
    Token(TokenCmd),
    Status(StatusCmd),
    Profiles(ProfilesCmd),
    Revoke(RevokeCmd),
    Prune(PruneCmd),
    Run(RunCmd),
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

    /// derived-profile repository selection (all, auto, or owner/repo; repeat to select repositories; rejected for root profiles)
    #[argh(option, short = 'r')]
    pub repo: Vec<String>,

    /// output format (text, json, or env)
    #[argh(option, short = 'f', default = "OutputFormat::Text")]
    pub format: OutputFormat,
}

/// Display active token and profile status.
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

/// Revoke all cached credentials and remove their local entries.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "revoke")]
pub struct RevokeCmd {
    /// required acknowledgement that every cached credential will be revoked
    #[argh(switch)]
    pub all: bool,
}

/// Remove expired entries and revoke tokens from abandoned runs.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "prune")]
pub struct PruneCmd {}

/// Run a command with a fresh derived GitHub token. Access that dies with the process.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "run")]
pub struct RunCmd {
    /// target derived profile name (override `GHST_PROFILE`)
    #[argh(option, short = 'p')]
    pub profile: Option<String>,

    /// derived-profile repository selection (all, auto, or owner/repo; repeat to select repositories)
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
        return Ok(profile.to_owned());
    }
    if let Ok(profile) = env::var("GHST_PROFILE") {
        let profile = profile.trim();
        if !profile.is_empty() {
            return Ok(profile.to_owned());
        }
    }
    config
        .default_profile
        .clone()
        .ok_or(CmdError::ProfileRequired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_cmd_parsing() {
        let args = GhstCli::from_args(&["ghst"], &["login", "--profile", "developer"]).unwrap();
        assert_eq!(
            args,
            GhstCli {
                config: None,
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
                command: SubCommand::Token(TokenCmd {
                    profile: Some("reader".to_string()),
                    repo: vec!["octo-org/repo1".to_string(), "octo-org/repo2".to_string()],
                    format: OutputFormat::Env,
                })
            }
        );
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
        assert!(matches!(
            GhstCli::from_args(&["ghst"], &["prune"]).unwrap().command,
            SubCommand::Prune(PruneCmd {})
        ));
        assert_eq!(
            GhstCli::from_args(&["ghst"], &["revoke", "--all"])
                .unwrap()
                .command,
            SubCommand::Revoke(RevokeCmd { all: true })
        );
    }

    #[test]
    fn test_profiles_cmd_parsing() {
        let args = GhstCli::from_args(&["ghst"], &["profiles"]).unwrap();
        assert_eq!(
            args,
            GhstCli {
                config: None,
                command: SubCommand::Profiles(ProfilesCmd { verbose: false }),
            }
        );

        let args_v = GhstCli::from_args(&["ghst"], &["profiles", "-v"]).unwrap();
        assert_eq!(
            args_v,
            GhstCli {
                config: None,
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
