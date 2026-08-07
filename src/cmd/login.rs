use crate::browser::{display_auth_instructions, open_auth_url};
use crate::cache::cache_epoch;
use crate::cmd::{CmdError, GhstCli, LoginCmd, resolve_profile_name};
use crate::config::ProfileConfig;
use crate::github::{GitHubClient, GitHubError};
use crate::token::RootPersistence;
use std::thread;
use time::OffsetDateTime;
use tracing::{debug, info, warn};

/// Handles execution of the `ghst login` subcommand.
pub fn run_login(args: &GhstCli, cmd: &LoginCmd) -> Result<(), CmdError> {
    let config = crate::config::load(args.config.as_deref())?;
    let profile_name = resolve_profile_name(cmd.profile.as_deref(), &config)?;
    let root_profile = match config.profiles.get(&profile_name) {
        Some(ProfileConfig::Root(root)) => root,
        Some(ProfileConfig::Derived(derived)) => {
            return Err(CmdError::DerivedLoginNotAllowed {
                profile: profile_name,
                source: derived.source.clone(),
            });
        }
        None => return Err(CmdError::ProfileNotFound(profile_name)),
    };

    let cache_dir = crate::config::cache_dir()?;
    debug!("Resolved cache directory: {:?}", cache_dir);
    if let Some(status) = crate::token::load_valid_root_status(
        &cache_dir,
        &profile_name,
        root_profile,
        OffsetDateTime::now_utc(),
    )? {
        debug!("Found valid cached root token for profile '{profile_name}'");
        report_existing(&profile_name, &status);
        return Ok(());
    }

    let client = GitHubClient::new();
    let epoch = cache_epoch(&cache_dir)?;
    info!("Initiating OAuth Device Flow for profile '{profile_name}'...");
    let device = client.request_device_code(&root_profile.github_app.client_id)?;
    display_auth_instructions(
        &root_profile.github_app.account,
        &device.user_code,
        &device.verification_uri,
    );
    open_auth_url(
        &device.verification_uri,
        cmd.no_browser || config.no_browser,
    );
    println!("Waiting for authorization in browser...");

    let mut interval = device.interval;
    let response = loop {
        thread::sleep(std::time::Duration::from_secs(interval));
        match client.poll_access_token(&root_profile.github_app.client_id, &device.device_code) {
            Ok(response) => break response,
            Err(GitHubError::OAuthPending) => {}
            Err(GitHubError::OAuthSlowDown) => {
                interval += 5;
                warn!("Polling rate limited by GitHub; increasing interval to {interval}s");
            }
            Err(GitHubError::OAuthExpired) => return Err(CmdError::OAuthExpired),
            Err(GitHubError::OAuthAccessDenied) => return Err(CmdError::OAuthAccessDenied),
            Err(error) => return Err(CmdError::GitHub(error)),
        }
    };

    match crate::token::persist_root_response(
        &client,
        root_profile,
        &profile_name,
        &cache_dir,
        response,
        OffsetDateTime::now_utc(),
        epoch,
    )? {
        RootPersistence::Saved(entry) => report_saved(&profile_name, &entry),
        RootPersistence::Retained(entry) => report_existing(&profile_name, &entry),
    }
    Ok(())
}

fn report_saved(profile_name: &str, status: &crate::token::RootTokenStatus) {
    println!(
        "Successfully authenticated as @{} for profile '{profile_name}'. Root token cached until {}.",
        status.github_user, status.expires_at
    );
}

fn report_existing(profile_name: &str, status: &crate::token::RootTokenStatus) {
    println!(
        "Profile '{profile_name}' already has a valid cached root token for @{} (valid until {}).",
        status.github_user, status.expires_at
    );
}
