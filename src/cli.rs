use argh::FromArgs;
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

    /// repository scope (all, auto, or owner/repo; may be specified multiple times)
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
pub struct ProfilesCmd {}

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
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "env" => Ok(Self::Env),
            other => Err(format!(
                "unknown output format '{other}', expected 'text', 'json', or 'env'"
            )),
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
    fn test_output_format_from_str() {
        assert_eq!("text".parse::<OutputFormat>(), Ok(OutputFormat::Text));
        assert_eq!("JSON".parse::<OutputFormat>(), Ok(OutputFormat::Json));
        assert_eq!("Env".parse::<OutputFormat>(), Ok(OutputFormat::Env));
        assert!("invalid".parse::<OutputFormat>().is_err());
    }
}
