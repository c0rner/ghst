use crate::browser::{display_auth_instructions, open_auth_url};
use crate::cache::{
    AccessToken, CACHE_SCHEMA_VERSION, CacheEntry, RootCacheEntry, SaveCacheEntry, TokenExpiry,
    authority_fingerprint, cache_epoch, format_rfc3339, save_cache_candidate,
};
use crate::cmd::{
    CmdError, GhstCli, LoginCmd, load_config, load_valid_root_entry, resolve_profile_name,
    revoke_with_context, root_cache_key,
};
use crate::config::ProfileConfig;
use crate::github::{AccessTokenResponse, GitHubClient, GitHubError, RootTokenClient};
use std::thread;
use time::{Duration, OffsetDateTime};
use tracing::{info, warn};

const MAX_ROOT_LIFETIME_SECONDS: u64 = 8 * 60 * 60;

/// Handles execution of the `ghst login` subcommand.
///
/// # Errors
///
/// Returns `CmdError` if configuration loading, profile resolution,
/// OAuth execution, lifetime validation, persistence, or cleanup fails.
pub fn run_login(args: &GhstCli, cmd: &LoginCmd) -> Result<(), CmdError> {
    let config = load_config(args.config.as_deref())?;
    let profile_name = resolve_profile_name(cmd.profile.as_deref(), &config)?;
    let profile = config
        .profiles
        .get(&profile_name)
        .ok_or_else(|| CmdError::ProfileNotFound(profile_name.clone()))?;
    let root_profile = match profile {
        ProfileConfig::Root(root) => root,
        ProfileConfig::Derived(derived) => {
            return Err(CmdError::DerivedLoginNotAllowed {
                profile: profile_name,
                source: derived.source.clone(),
            });
        }
    };

    let cache_dir = crate::config::Config::cache_dir()?;
    if let Some(entry) = load_valid_root_entry(
        &cache_dir,
        &profile_name,
        root_profile,
        OffsetDateTime::now_utc(),
    )? {
        report_existing(&profile_name, &entry);
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
        cmd.no_browser || config.no_browser.unwrap_or(false),
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

    persist_root_response(
        &client,
        root_profile,
        &profile_name,
        &cache_dir,
        response,
        OffsetDateTime::now_utc(),
        epoch,
    )
}

fn persist_root_response<C: RootTokenClient>(
    client: &C,
    profile: &crate::config::RootProfile,
    profile_name: &str,
    cache_dir: &std::path::Path,
    response: AccessTokenResponse,
    now: OffsetDateTime,
    epoch: u64,
) -> Result<(), CmdError> {
    let AccessTokenResponse {
        access_token,
        expires_in,
        refresh_token,
        ..
    } = response;
    drop(refresh_token);

    let expiry = match validate_root_expiry(expires_in, now) {
        Ok(expiry) => expiry,
        Err(error) => return Err(revoke_with_context(client, profile, &access_token, error)),
    };
    let user = match client.get_user(access_token.as_ref()) {
        Ok(user) => user,
        Err(error) => {
            return Err(revoke_with_context(
                client,
                profile,
                &access_token,
                CmdError::GitHub(error),
            ));
        }
    };

    let candidate = CacheEntry::Root(RootCacheEntry {
        version: CACHE_SCHEMA_VERSION,
        profile: profile_name.to_owned(),
        authority_fingerprint: authority_fingerprint(
            &profile.github_app.client_id,
            &profile.github_app.account,
        ),
        github_user: user.login,
        issued_at: format_rfc3339(now),
        expires_at: expiry,
        access_token,
    });
    let key = root_cache_key(profile_name);
    let result = match save_cache_candidate(cache_dir, &key, &candidate, epoch, None) {
        Ok(result) => result,
        Err(error) => {
            return Err(revoke_with_context(
                client,
                profile,
                root_token(&candidate)?,
                CmdError::Cache(error),
            ));
        }
    };

    match result {
        SaveCacheEntry::Saved => report_saved(profile_name, root_entry(&candidate)?),
        SaveCacheEntry::Retained(entry) => match *entry {
            CacheEntry::Root(entry) => {
                if let Err(source) = client.delete_token(
                    &profile.github_app.client_id,
                    &profile.github_app.client_secret,
                    root_token(&candidate)?.as_ref(),
                ) {
                    return Err(CmdError::RevocationFailed {
                        context: Box::new(CmdError::StaleProvenance {
                            profile: profile_name.to_owned(),
                            reason: "a compatible concurrent root cache winner was retained",
                        }),
                        source,
                    });
                }
                report_existing(profile_name, &entry);
            }
            entry @ CacheEntry::Derived(_) => {
                return Err(CmdError::UnexpectedCacheKind {
                    profile: profile_name.to_owned(),
                    expected: crate::cache::CacheKind::Root,
                    actual: entry.kind(),
                });
            }
        },
    }
    Ok(())
}

fn validate_root_expiry(
    expires_in: Option<u64>,
    now: OffsetDateTime,
) -> Result<TokenExpiry, CmdError> {
    let seconds = expires_in.ok_or_else(|| CmdError::InvalidLifetime {
        token_kind: "root",
        reason: "response did not contain expires_in".into(),
    })?;
    if seconds == 0 {
        return Err(CmdError::InvalidLifetime {
            token_kind: "root",
            reason: "expires_in must be positive".into(),
        });
    }
    if seconds > MAX_ROOT_LIFETIME_SECONDS {
        return Err(CmdError::InvalidLifetime {
            token_kind: "root",
            reason: format!(
                "expires_in of {seconds} seconds exceeds the supported eight-hour maximum"
            ),
        });
    }
    let seconds = i64::try_from(seconds).map_err(|_| CmdError::InvalidLifetime {
        token_kind: "root",
        reason: "expires_in cannot be represented safely".into(),
    })?;
    let expiry = TokenExpiry::new(now + Duration::seconds(seconds));
    if !expiry.is_usable_at(now) {
        return Err(CmdError::InvalidLifetime {
            token_kind: "root",
            reason: "expires_in is not beyond the 30-second safety margin".into(),
        });
    }
    Ok(expiry)
}

fn root_entry(entry: &CacheEntry) -> Result<&RootCacheEntry, CmdError> {
    entry
        .as_root()
        .ok_or_else(|| CmdError::UnexpectedCacheKind {
            profile: entry.profile().to_owned(),
            expected: crate::cache::CacheKind::Root,
            actual: entry.kind(),
        })
}

fn root_token(entry: &CacheEntry) -> Result<&AccessToken, CmdError> {
    root_entry(entry).map(|root| &root.access_token)
}

fn report_saved(profile_name: &str, entry: &RootCacheEntry) {
    println!(
        "Successfully authenticated as @{} for profile '{profile_name}'. Root token cached until {}.",
        entry.github_user, entry.expires_at
    );
}

fn report_existing(profile_name: &str, entry: &RootCacheEntry) {
    println!(
        "Profile '{profile_name}' already has a valid cached root token for @{} (valid until {}).",
        entry.github_user, entry.expires_at
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::SubCommand;
    use crate::github::{RevokeTokenClient, UserResponse};
    use argh::FromArgs;
    use std::cell::RefCell;

    const CONFIG: &str = r#"
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
    fn derived_login_is_rejected() {
        let config: crate::config::Config = CONFIG.parse().unwrap();
        let args = GhstCli::from_args(&["ghst"], &["login", "-p", "reader"]).unwrap();
        let SubCommand::Login(command) = &args.command else {
            panic!("expected login command");
        };
        let profile_name = resolve_profile_name(command.profile.as_deref(), &config).unwrap();
        let ProfileConfig::Derived(derived) = config.profiles.get(&profile_name).unwrap() else {
            panic!("expected derived profile");
        };
        let error = CmdError::DerivedLoginNotAllowed {
            profile: profile_name,
            source: derived.source.clone(),
        };
        assert!(error.to_string().contains("ghst login -p developer"));
    }

    #[test]
    fn root_lifetime_requires_positive_bounded_value_and_margin() {
        let now = OffsetDateTime::now_utc();
        for value in [None, Some(0), Some(30), Some(MAX_ROOT_LIFETIME_SECONDS + 1)] {
            assert!(matches!(
                validate_root_expiry(value, now),
                Err(CmdError::InvalidLifetime { .. })
            ));
        }
        assert_eq!(
            validate_root_expiry(Some(MAX_ROOT_LIFETIME_SECONDS), now)
                .unwrap()
                .value(),
            now + Duration::hours(8)
        );
    }

    #[test]
    fn refresh_token_is_redacted_and_access_token_is_not_clone() {
        let response: AccessTokenResponse = serde_json::from_str(
            r#"{"access_token":"access","token_type":"bearer","expires_in":3600,"refresh_token":"refresh"}"#,
        )
        .unwrap();
        let debug = format!("{response:?}");
        assert!(!debug.contains("\"access\""));
        assert!(!debug.contains("\"refresh\""));
    }

    struct MockRootClient {
        revoked: RefCell<Vec<String>>,
        revoke_fails: bool,
    }

    impl RevokeTokenClient for MockRootClient {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            access_token: &str,
        ) -> Result<(), GitHubError> {
            self.revoked.borrow_mut().push(access_token.to_owned());
            if self.revoke_fails {
                Err(GitHubError::Http {
                    status: 500,
                    message: "revocation failed".into(),
                })
            } else {
                Ok(())
            }
        }
    }

    impl RootTokenClient for MockRootClient {
        fn get_user(&self, _access_token: &str) -> Result<UserResponse, GitHubError> {
            Ok(UserResponse {
                login: "octocat".into(),
                id: 1,
                name: None,
                email: None,
            })
        }
    }

    fn invalid_response() -> AccessTokenResponse {
        AccessTokenResponse {
            access_token: "new-root".into(),
            token_type: "bearer".into(),
            expires_in: None,
            refresh_token: Some(zeroize::Zeroizing::new("refresh".into())),
            refresh_token_expires_in: Some(3600),
            scope: None,
        }
    }

    #[test]
    fn invalid_root_lifetime_revokes_without_writing_cache() {
        let config: crate::config::Config = CONFIG.parse().unwrap();
        let ProfileConfig::Root(profile) = config.profiles.get("developer").unwrap() else {
            panic!("expected root profile");
        };
        let client = MockRootClient {
            revoked: RefCell::new(Vec::new()),
            revoke_fails: false,
        };
        let temp = tempfile::tempdir().unwrap();
        let error = persist_root_response(
            &client,
            profile,
            "developer",
            &temp.path().join("cache"),
            invalid_response(),
            OffsetDateTime::now_utc(),
            cache_epoch(&temp.path().join("cache")).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(error, CmdError::InvalidLifetime { .. }));
        assert_eq!(&*client.revoked.borrow(), &["new-root"]);
        assert!(
            crate::cache::list_all_cache_entries(&temp.path().join("cache"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn revocation_failure_preserves_lifetime_failure_context() {
        let config: crate::config::Config = CONFIG.parse().unwrap();
        let ProfileConfig::Root(profile) = config.profiles.get("developer").unwrap() else {
            panic!("expected root profile");
        };
        let client = MockRootClient {
            revoked: RefCell::new(Vec::new()),
            revoke_fails: true,
        };
        let temp = tempfile::tempdir().unwrap();
        let error = persist_root_response(
            &client,
            profile,
            "developer",
            &temp.path().join("cache"),
            invalid_response(),
            OffsetDateTime::now_utc(),
            cache_epoch(&temp.path().join("cache")).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CmdError::RevocationFailed { context, .. }
                if matches!(*context, CmdError::InvalidLifetime { .. })
        ));
    }
}
