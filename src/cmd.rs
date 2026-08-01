pub mod clear;
pub mod error;
pub mod login;
pub mod profiles;
pub mod proxy;
mod repository;
pub mod status;
pub mod token;

pub use error::CmdError;
use repository::RepositorySelection;

use crate::cache::{
    CacheEntry, CacheKind, LegacyCacheEntry, RootCacheEntry, authority_fingerprint,
    compute_cache_key, load_cache_entry,
};
use crate::config::{Config, RootProfile};
use argh::FromArgs;
use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

/// GitHub Scoped Token Helper.
#[derive(FromArgs, PartialEq, Eq, Debug)]
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
    Clear(ClearCmd),
    Proxy(ProxyCmd),
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

/// Clear cached tokens.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "clear")]
pub struct ClearCmd {}

/// Run IPC proxy daemon for host isolation (v2).
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "proxy")]
pub struct ProxyCmd {
    /// unix domain socket path
    #[argh(option, short = 's')]
    pub socket: Option<PathBuf>,

    /// allowed profile name (may be specified multiple times to restrict proxy execution)
    #[argh(option, short = 'a')]
    pub allow_profile: Vec<String>,
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

fn load_config(path: Option<&Path>) -> Result<Config, CmdError> {
    path.map_or_else(Config::load, Config::load_from_path)
        .map_err(CmdError::Config)
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

fn root_cache_key(profile_name: &str) -> String {
    compute_cache_key(profile_name, "all")
}

fn load_valid_root_entry(
    cache_dir: &Path,
    profile_name: &str,
    profile: &RootProfile,
    now: time::OffsetDateTime,
) -> Result<Option<RootCacheEntry>, CmdError> {
    Ok(load_current_root_entry(cache_dir, profile_name, profile)?
        .filter(|entry| entry.expires_at.is_usable_at(now)))
}

fn load_current_root_entry(
    cache_dir: &Path,
    profile_name: &str,
    profile: &RootProfile,
) -> Result<Option<RootCacheEntry>, CmdError> {
    let key = root_cache_key(profile_name);
    let Some(entry) = load_cache_entry(cache_dir, &key)? else {
        return Ok(None);
    };

    if entry.profile() != profile_name {
        return Err(CmdError::InconsistentCacheMetadata {
            profile: profile_name.to_owned(),
            found: entry.profile().to_owned(),
        });
    }

    match entry {
        CacheEntry::Root(entry) => {
            let expected_authority =
                authority_fingerprint(&profile.github_app.client_id, &profile.github_app.account);
            if entry.version == crate::cache::CACHE_SCHEMA_VERSION
                && entry.authority_fingerprint == expected_authority
            {
                Ok(Some(entry))
            } else {
                Ok(None)
            }
        }
        CacheEntry::Legacy(LegacyCacheEntry::Root(_)) => Ok(None),
        CacheEntry::Derived(_) | CacheEntry::Legacy(LegacyCacheEntry::Derived(_)) => {
            Err(CmdError::UnexpectedCacheKind {
                profile: profile_name.to_owned(),
                expected: CacheKind::Root,
                actual: CacheKind::Derived,
            })
        }
    }
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
    fn test_proxy_cmd_allowed_profiles() {
        let args = GhstCli::from_args(
            &["ghst"],
            &[
                "proxy",
                "--socket",
                "/tmp/ghst.sock",
                "--allow-profile",
                "reader",
                "--allow-profile",
                "contributor",
            ],
        )
        .unwrap();
        assert_eq!(
            args,
            GhstCli {
                config: None,
                command: SubCommand::Proxy(ProxyCmd {
                    socket: Some(PathBuf::from("/tmp/ghst.sock")),
                    allow_profile: vec!["reader".to_string(), "contributor".to_string()],
                })
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
