use crate::browser::BrowserAuthorizationPresenter;
use crate::cache::CacheStore;
use crate::cmd::{CmdError, GhstCli, LoginCmd, format_human_expiry, resolve_profile_name};
use crate::github::GitHubClient;
use crate::profile::{NamedAppRegistration, ResolvedTokenProfile};
use crate::token::{LoginOutcome, authenticate};

/// Handles execution of the `ghst login` subcommand.
pub fn run_login(args: &GhstCli, cmd: &LoginCmd) -> Result<(), CmdError> {
    let config = crate::config::load(args.config.as_deref())?;
    let profile_name = resolve_profile_name(cmd.profile.as_deref(), &config)?;
    let app = match config.resolve_token_profile(&profile_name)? {
        ResolvedTokenProfile::Base { app, .. } => NamedAppRegistration {
            profile_name: &profile_name,
            app,
        },
        ResolvedTokenProfile::Scoped { source_name, .. } => {
            return Err(CmdError::ScopedLoginNotAllowed {
                profile: profile_name,
                source: source_name.to_owned(),
            });
        }
    };

    let cache_dir = crate::config::cache_dir()?;
    let store = CacheStore::new(&cache_dir);
    let client = GitHubClient::new();
    let presenter =
        BrowserAuthorizationPresenter::new(no_browser(cmd.no_browser, config.no_browser));
    match authenticate(&client, &store, &presenter, app)? {
        LoginOutcome::Authenticated(status) => {
            report_saved(&profile_name, &status);
        }
        LoginOutcome::AlreadyAuthenticated(status) => {
            report_existing(&profile_name, &status);
        }
    }
    Ok(())
}

fn report_saved(profile_name: &str, status: &crate::token::BaseTokenStatus) {
    println!("{}", saved_message(profile_name, status));
}

fn saved_message(profile_name: &str, status: &crate::token::BaseTokenStatus) -> String {
    format!(
        "Successfully authenticated as @{} for profile '{profile_name}'. Base token cached until {}.",
        status.github_user,
        format_human_expiry(status.expires_at)
    )
}

fn report_existing(profile_name: &str, status: &crate::token::BaseTokenStatus) {
    println!("{}", existing_message(profile_name, status));
}

fn existing_message(profile_name: &str, status: &crate::token::BaseTokenStatus) -> String {
    format!(
        "Profile '{profile_name}' already has a valid cached base token for @{} (valid until {}).",
        status.github_user,
        format_human_expiry(status.expires_at)
    )
}

const fn no_browser(command_line: bool, configured: bool) -> bool {
    command_line || configured
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::TokenExpiry;
    use time::OffsetDateTime;

    fn status() -> crate::token::BaseTokenStatus {
        crate::token::BaseTokenStatus {
            github_user: "octocat".into(),
            expires_at: TokenExpiry::new(OffsetDateTime::UNIX_EPOCH),
        }
    }

    #[test]
    fn login_result_messages_are_exact() {
        let status = status();
        let expiry = format_human_expiry(status.expires_at);
        assert_eq!(
            saved_message("developer", &status),
            format!(
                "Successfully authenticated as @octocat for profile 'developer'. Base token cached until {expiry}."
            )
        );
        assert_eq!(
            existing_message("developer", &status),
            format!(
                "Profile 'developer' already has a valid cached base token for @octocat (valid until {expiry})."
            )
        );
    }

    #[test]
    fn no_browser_flag_is_cli_or_configuration() {
        assert!(!no_browser(false, false));
        assert!(no_browser(true, false));
        assert!(no_browser(false, true));
        assert!(no_browser(true, true));
    }
}
