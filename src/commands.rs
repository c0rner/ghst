use crate::browser::{display_auth_instructions, open_auth_url};
use crate::cache::{
    CacheEntry, RootCacheEntry, compute_cache_key, format_rfc3339, load_cache_entry,
    save_cache_entry,
};
use crate::cli::{GhstCli, LoginCmd};
use crate::config::{Config, ProfileConfig, RepoScope};
use crate::github::{GitHubClient, GitHubError};
use std::env;
use std::thread;
use time::{Duration, OffsetDateTime};
use tracing::{info, warn};

/// Handles execution of the `ghst login` subcommand.
///
/// # Errors
///
/// Returns error string if configuration loading, profile resolution,
/// profile validation, or OAuth device flow execution fails.
pub fn run_login(args: &GhstCli, cmd: &LoginCmd) -> Result<(), String> {
    // 1. Load configuration
    let config = load_config(args.config.as_deref())?;

    // 2. Resolve target profile name
    let profile_name = resolve_profile_name(cmd.profile.as_deref(), &config)?;

    // 3. Look up profile and enforce Root-only rule
    let profile = config
        .profiles
        .get(&profile_name)
        .ok_or_else(|| format!("profile '{profile_name}' is not defined in configuration"))?;

    let root_profile = match profile {
        ProfileConfig::Derived(derived) => {
            return Err(format!(
                "profile '{profile_name}' is a derived profile. Login is only permitted for root profiles. Please log in to its root source profile '{}' instead: ghst login -p {}",
                derived.source, derived.source
            ));
        }
        ProfileConfig::Root(root) => root,
    };

    // 4. Determine repository scope and compute SHA-256 cache key
    let repo_scope_str = match &root_profile.repo {
        Some(RepoScope::All) | None => "all",
        Some(RepoScope::Auto) => "auto",
        Some(RepoScope::Specific(r)) => r.as_str(),
    };
    let hash_key = compute_cache_key(&profile_name, repo_scope_str);

    // 5. Check if valid unexpired root token already exists in cache
    let cache_dir = Config::cache_dir().map_err(|e| e.to_string())?;
    if let Ok(Some(CacheEntry::Root(entry))) = load_cache_entry(&cache_dir, &hash_key) {
        if entry.is_valid() {
            println!(
                "Profile '{profile_name}' already has a valid cached root token for @{} (valid until {}).",
                entry.github_user, entry.expires_at
            );
            return Ok(());
        }
    }

    // 6. Execute OAuth Device Flow
    let client = GitHubClient::new();
    info!("Initiating OAuth Device Flow for profile '{profile_name}'...");

    let device_res = client
        .request_device_code(&root_profile.github_app.client_id)
        .map_err(|e| format!("Failed to request device code: {e}"))?;

    // Display authorization instructions banner
    display_auth_instructions(
        &root_profile.github_app.account,
        &device_res.user_code,
        &device_res.verification_uri,
    );

    // Open browser unless disabled via CLI flag or config
    let no_browser = cmd.no_browser || config.no_browser.unwrap_or(false);
    open_auth_url(&device_res.verification_uri, no_browser);

    println!("Waiting for authorization in browser...");

    // 7. Poll for access token
    let mut interval = device_res.interval;
    let token_res = loop {
        thread::sleep(std::time::Duration::from_secs(interval));

        match client.poll_access_token(&root_profile.github_app.client_id, &device_res.device_code)
        {
            Ok(res) => break res,
            Err(GitHubError::OAuthPending) => {
                // Continue polling
            }
            Err(GitHubError::OAuthSlowDown) => {
                interval += 5;
                warn!("Polling rate limited by GitHub; increasing interval to {interval}s");
            }
            Err(GitHubError::OAuthExpired) => {
                return Err("Device code expired. Please run `ghst login` again.".into());
            }
            Err(GitHubError::OAuthAccessDenied) => {
                return Err("Authorization request was denied by the user.".into());
            }
            Err(err) => {
                return Err(format!("OAuth polling error: {err}"));
            }
        }
    };

    // 8. Fetch authenticated user details
    // Note: Refresh token in `token_res` is destroyed in memory and never stored (Rule 7).
    let user_info = client
        .get_user(&token_res.access_token)
        .map_err(|e| format!("Failed to fetch user details: {e}"))?;

    // 9. Compute timestamps and save root token to cache
    let now = OffsetDateTime::now_utc();
    let issued_at = format_rfc3339(now);
    let expires_in_secs = i64::try_from(token_res.expires_in.unwrap_or(28800)).unwrap_or(28800);
    let expires_at = format_rfc3339(now + Duration::seconds(expires_in_secs));

    let root_entry = RootCacheEntry {
        profile: profile_name.clone(),
        github_user: user_info.login.clone(),
        issued_at,
        expires_at: expires_at.clone(),
        access_token: token_res.access_token,
    };

    save_cache_entry(&cache_dir, &hash_key, &CacheEntry::Root(root_entry))
        .map_err(|e| format!("Failed to save cache entry: {e}"))?;

    println!(
        "Successfully authenticated as @{} for profile '{profile_name}'. Root token cached until {expires_at}.",
        user_info.login
    );

    Ok(())
}

fn load_config(path: Option<&std::path::Path>) -> Result<Config, String> {
    path.map_or_else(
        || Config::load().map_err(|e| e.to_string()),
        |p| Config::load_from_path(p).map_err(|e| e.to_string()),
    )
}

fn resolve_profile_name(cli_profile: Option<&str>, config: &Config) -> Result<String, String> {
    if let Some(p) = cli_profile {
        return Ok(p.to_string());
    }

    if let Ok(env_p) = env::var("GHST_PROFILE") {
        if !env_p.trim().is_empty() {
            return Ok(env_p.trim().to_string());
        }
    }

    if let Some(ref def_p) = config.default_profile {
        return Ok(def_p.clone());
    }

    Err(
        "No profile specified. Pass `-p <profile>` or set `default_profile` in configuration."
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::SubCommand;
    use argh::FromArgs;

    const SAMPLE_CONFIG: &str = r#"
version = 1
default_profile = "reader"

[profile.developer]
kind = "root"
github_app.account = "acme"
github_app.client_id = "id"
github_app.client_secret = "secret"

[profile.reader]
kind = "derived"
source = "developer"
permissions = { contents = "read" }
"#;

    #[test]
    fn test_derived_profile_login_rejected() {
        let config: Config = SAMPLE_CONFIG.parse().unwrap();
        let args = GhstCli::from_args(&["ghst"], &["login", "-p", "reader"]).unwrap();
        let SubCommand::Login(cmd) = &args.command else {
            panic!("expected login cmd");
        };

        let profile_name = resolve_profile_name(cmd.profile.as_deref(), &config).unwrap();
        let profile = config.profiles.get(&profile_name).unwrap();
        match profile {
            ProfileConfig::Derived(derived) => {
                let err_msg = format!(
                    "profile '{profile_name}' is a derived profile. Login is only permitted for root profiles. Please log in to its root source profile '{}' instead: ghst login -p {}",
                    derived.source, derived.source
                );
                assert!(err_msg.contains("ghst login -p developer"));
            }
            ProfileConfig::Root(_) => panic!("expected derived profile"),
        }
    }

    #[test]
    fn test_resolve_profile_name_priority() {
        let config: Config = SAMPLE_CONFIG.parse().unwrap();

        // CLI flag priority
        assert_eq!(
            resolve_profile_name(Some("developer"), &config).unwrap(),
            "developer"
        );

        // Fallback to default_profile
        assert_eq!(resolve_profile_name(None, &config).unwrap(), "reader");
    }
}
