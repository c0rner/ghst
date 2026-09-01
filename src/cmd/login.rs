use crate::browser::{display_auth_instructions, open_auth_url};
use crate::cache::cache_epoch;
use crate::cmd::{CmdError, GhstCli, LoginCmd, format_human_expiry, resolve_profile_name};
use crate::config::ProfileConfig;
use crate::github::GitHubClient;
use crate::token::{BasePersistence, DeviceFlow};
use time::OffsetDateTime;
use tracing::{debug, info};

/// Handles execution of the `ghst login` subcommand.
pub fn run_login(args: &GhstCli, cmd: &LoginCmd) -> Result<(), CmdError> {
    let config = crate::config::load(args.config.as_deref())?;
    let profile_name = resolve_profile_name(cmd.profile.as_deref(), &config)?;
    let app_profile = match config.profiles.get(&profile_name) {
        Some(ProfileConfig::App(app)) => app,
        Some(ProfileConfig::Scoped(scoped)) => {
            return Err(CmdError::ScopedLoginNotAllowed {
                profile: profile_name,
                source: scoped.source.clone(),
            });
        }
        None => return Err(CmdError::ProfileNotFound(profile_name)),
    };

    let cache_dir = crate::config::cache_dir()?;
    debug!(
        profile = profile_name,
        "checking for a reusable cached base token"
    );
    if let Some(status) = crate::token::load_valid_base_status(
        &cache_dir,
        &profile_name,
        app_profile,
        OffsetDateTime::now_utc(),
    )? {
        debug!(
            profile = profile_name,
            github_user = status.github_user,
            expires_at = %status.expires_at,
            "reusing cached base token"
        );
        report_existing(&profile_name, &status);
        return Ok(());
    }

    let client = GitHubClient::new();
    let mut flow = DeviceFlow::new(&client, std::thread::sleep, &profile_name);
    let epoch = cache_epoch(&cache_dir)?;
    info!(profile = profile_name, "initiating OAuth Device Flow");
    let device = flow.request_authorization(&app_profile.github_app.client_id)?;
    display_auth_instructions(
        &app_profile.github_app.account,
        &device.user_code,
        &device.verification_uri,
    );
    open_auth_url(
        &device.verification_uri,
        cmd.no_browser || config.no_browser,
    );
    println!("Waiting for authorization in browser...");

    debug!(
        profile = profile_name,
        expires_in_seconds = device.expires_in.as_secs(),
        poll_interval_seconds = device.interval.as_secs(),
        "device authorization request created"
    );
    let response = flow.poll_authorization(&app_profile.github_app.client_id, &device)?;
    debug!(
        profile = profile_name,
        "device authorization completed; validating and caching base token"
    );

    match crate::token::persist_base_response(
        &client,
        app_profile,
        &profile_name,
        &cache_dir,
        response,
        OffsetDateTime::now_utc(),
        epoch,
    )? {
        BasePersistence::Saved(entry) => {
            debug!(profile = profile_name, expires_at = %entry.expires_at, "cached new base token");
            report_saved(&profile_name, &entry);
        }
        BasePersistence::Retained(entry) => {
            debug!(profile = profile_name, expires_at = %entry.expires_at, "retained compatible base token cached by a concurrent login");
            report_existing(&profile_name, &entry);
        }
    }
    Ok(())
}

fn report_saved(profile_name: &str, status: &crate::token::BaseTokenStatus) {
    println!(
        "Successfully authenticated as @{} for profile '{profile_name}'. Base token cached until {}.",
        status.github_user,
        format_human_expiry(status.expires_at)
    );
}

fn report_existing(profile_name: &str, status: &crate::token::BaseTokenStatus) {
    println!(
        "Profile '{profile_name}' already has a valid cached base token for @{} (valid until {}).",
        status.github_user,
        format_human_expiry(status.expires_at)
    );
}
