use crate::browser::{display_auth_instructions, open_auth_url};
use crate::cache::{
    CacheEntry, RootCacheEntry, SaveCacheEntry, compute_cache_key, format_rfc3339,
    load_cache_entry, save_cache_entry,
};
use crate::cmd::{GhstCli, LoginCmd};
use crate::config::{Config, ProfileConfig, RepoScope};
use crate::github::{AccessTokenResponse, GitHubClient, GitHubError};
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

    // 4. Resolve repository scope and compute SHA-256 cache key
    let repo_scope =
        resolve_root_repo_scope_with(root_profile.repo.as_ref(), crate::git::resolve_origin_repo)?;
    let hash_key = compute_cache_key(&profile_name, &repo_scope);

    // 5. Check if valid unexpired root token already exists in cache
    let cache_dir = Config::cache_dir().map_err(|e| e.to_string())?;
    if let Some(entry) = load_valid_root_cache_entry(&cache_dir, &hash_key, &profile_name)? {
        println!(
            "Profile '{profile_name}' already has a valid cached root token for @{} (valid until {}).",
            entry.github_user, entry.expires_at
        );
        return Ok(());
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

    let (access_token, expires_in) = extract_access_token(token_res);

    // 8. Fetch authenticated user details
    let user_info = client
        .get_user(&access_token)
        .map_err(|e| format!("Failed to fetch user details: {e}"))?;

    // 9. Compute timestamps and save root token to cache
    let now = OffsetDateTime::now_utc();
    let issued_at = format_rfc3339(now);
    let expires_in_secs = i64::try_from(expires_in.unwrap_or(28800)).unwrap_or(28800);
    let expires_at = format_rfc3339(now + Duration::seconds(expires_in_secs));

    let root_entry = RootCacheEntry {
        profile: profile_name.clone(),
        github_user: user_info.login.clone(),
        issued_at,
        expires_at: expires_at.clone(),
        access_token,
    };

    report_root_cache_save(
        save_cache_entry(&cache_dir, &hash_key, &CacheEntry::Root(root_entry))
            .map_err(|err| format!("Failed to save cache entry: {err}"))?,
        &profile_name,
        &user_info.login,
        &expires_at,
    )?;

    Ok(())
}

fn load_valid_root_cache_entry(
    cache_dir: &std::path::Path,
    hash_key: &str,
    profile_name: &str,
) -> Result<Option<RootCacheEntry>, String> {
    match load_cache_entry(cache_dir, hash_key).map_err(|err| err.to_string())? {
        Some(CacheEntry::Root(entry)) if entry.is_valid() => Ok(Some(entry)),
        Some(entry) if entry.is_valid() => Err(format!(
            "valid cache entry for profile '{profile_name}' has unexpected kind '{}'",
            entry_kind(&entry)
        )),
        Some(_) | None => Ok(None),
    }
}

fn report_root_cache_save(
    outcome: SaveCacheEntry,
    profile_name: &str,
    github_user: &str,
    expires_at: &str,
) -> Result<(), String> {
    match outcome {
        SaveCacheEntry::Saved => println!(
            "Successfully authenticated as @{github_user} for profile '{profile_name}'. Root token cached until {expires_at}."
        ),
        SaveCacheEntry::Retained(CacheEntry::Root(entry)) => println!(
            "Profile '{profile_name}' already has a valid cached root token for @{} (valid until {}).",
            entry.github_user, entry.expires_at
        ),
        SaveCacheEntry::Retained(entry) => {
            return Err(format!(
                "valid cache entry for profile '{profile_name}' has unexpected kind '{}'",
                entry_kind(&entry)
            ));
        }
    }
    Ok(())
}

const fn entry_kind(entry: &CacheEntry) -> &'static str {
    match entry {
        CacheEntry::Root(_) => "root",
        CacheEntry::Derived(_) => "derived",
    }
}

fn extract_access_token(response: AccessTokenResponse) -> (String, Option<u64>) {
    let AccessTokenResponse {
        access_token,
        expires_in,
        refresh_token,
        ..
    } = response;
    drop(refresh_token);
    (access_token, expires_in)
}

#[cfg(test)]
fn resolve_root_repo_scope_from(
    repo_scope: Option<&RepoScope>,
    start_dir: &std::path::Path,
) -> Result<String, String> {
    resolve_root_repo_scope_with(repo_scope, || {
        crate::git::resolve_origin_repo_from(start_dir)
    })
}

fn resolve_root_repo_scope_with(
    repo_scope: Option<&RepoScope>,
    resolve_auto: impl FnOnce() -> Result<String, crate::git::GitError>,
) -> Result<String, String> {
    match repo_scope {
        Some(RepoScope::Auto) => resolve_auto()
            .map_err(|err| format!("failed to resolve automatic repository scope: {err}")),
        Some(RepoScope::All) | None => Ok("all".to_string()),
        Some(RepoScope::Specific(repo)) => Ok(repo.clone()),
    }
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
    use crate::cache::compute_cache_key;
    use crate::cmd::SubCommand;
    use argh::FromArgs;
    use std::fs;

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

    #[test]
    fn test_extract_access_token_drops_refresh_token() {
        let response = AccessTokenResponse {
            access_token: "access-token".into(),
            token_type: "bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some("refresh-token".to_string().into()),
            refresh_token_expires_in: Some(3600),
            scope: None,
        };

        assert_eq!(
            extract_access_token(response),
            ("access-token".to_string(), Some(3600))
        );
    }

    #[test]
    fn test_resolve_root_repo_scope_variants() {
        let temp_dir = tempfile::tempdir().unwrap();
        let specific = RepoScope::Specific("octo-org/api".into());

        assert_eq!(
            resolve_root_repo_scope_from(None, temp_dir.path()).unwrap(),
            "all"
        );
        assert_eq!(
            resolve_root_repo_scope_from(Some(&RepoScope::All), temp_dir.path()).unwrap(),
            "all"
        );
        assert_eq!(
            resolve_root_repo_scope_from(Some(&specific), temp_dir.path()).unwrap(),
            "octo-org/api"
        );
    }

    #[test]
    fn test_resolve_auto_root_repo_scope_to_canonical_origin() {
        let temp_dir = tempfile::tempdir().unwrap();
        write_origin_config(temp_dir.path(), "git@github.com:octo-org/api.git");

        let auto = RepoScope::Auto;
        assert_eq!(
            resolve_root_repo_scope_from(Some(&auto), temp_dir.path()).unwrap(),
            "octo-org/api"
        );
    }

    #[test]
    fn test_resolve_auto_root_repo_scope_fails_without_github_origin() {
        let temp_dir = tempfile::tempdir().unwrap();
        write_origin_config(temp_dir.path(), "git@gitlab.com:octo-org/api.git");

        let error =
            resolve_root_repo_scope_from(Some(&RepoScope::Auto), temp_dir.path()).unwrap_err();
        assert!(error.contains("failed to resolve automatic repository scope"));
        assert!(error.contains("not a GitHub repository"));
    }

    #[test]
    fn test_auto_root_repo_scopes_produce_distinct_cache_keys() {
        let first_dir = tempfile::tempdir().unwrap();
        let second_dir = tempfile::tempdir().unwrap();
        write_origin_config(first_dir.path(), "git@github.com:octo-org/first.git");
        write_origin_config(second_dir.path(), "git@github.com:octo-org/second.git");

        let auto = RepoScope::Auto;
        let first_scope = resolve_root_repo_scope_from(Some(&auto), first_dir.path()).unwrap();
        let second_scope = resolve_root_repo_scope_from(Some(&auto), second_dir.path()).unwrap();

        assert_ne!(
            compute_cache_key("developer", &first_scope),
            compute_cache_key("developer", &second_scope)
        );
    }

    fn write_origin_config(directory: &std::path::Path, origin_url: &str) {
        let git_dir = directory.join(".git");
        fs::create_dir(&git_dir).unwrap();
        fs::write(
            git_dir.join("config"),
            format!("[remote \"origin\"]\n\turl = {origin_url}\n"),
        )
        .unwrap();
    }
}
