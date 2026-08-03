use crate::cache::{CacheEntry, CacheInspectionState, clear_transaction};
use crate::cmd::{ClearCmd, CmdError, GhstCli, load_config};
use crate::config::{Config, ProfileConfig, RootProfile};
use crate::github::{GitHubClient, GitHubError, RevokeTokenClient};
use std::io::{self, Write};
use std::path::Path;
use time::OffsetDateTime;

pub enum ClearFailure {
    MissingAppCredentials {
        entry: String,
    },
    ClientSecretUnavailable {
        entry: String,
    },
    GitHubRevocation {
        entry: String,
        source: GitHubError,
    },
    CacheDeletion {
        entry: String,
        source: crate::cache::CacheError,
    },
}

impl std::fmt::Debug for ClearFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAppCredentials { entry } => formatter
                .debug_struct("MissingAppCredentials")
                .field("entry", entry)
                .finish(),
            Self::ClientSecretUnavailable { entry } => formatter
                .debug_struct("ClientSecretUnavailable")
                .field("entry", entry)
                .finish(),
            Self::GitHubRevocation { entry, source } => formatter
                .debug_struct("GitHubRevocation")
                .field("entry", entry)
                .field("source_kind", &github_error_kind(source))
                .finish(),
            Self::CacheDeletion { entry, source } => formatter
                .debug_struct("CacheDeletion")
                .field("entry", entry)
                .field("source", source)
                .finish(),
        }
    }
}

const fn github_error_kind(error: &GitHubError) -> &'static str {
    match error {
        GitHubError::Io(_) => "io",
        GitHubError::Json(_) => "json",
        GitHubError::Http { .. } => "http",
        GitHubError::OAuthPending => "oauth_pending",
        GitHubError::OAuthSlowDown => "oauth_slow_down",
        GitHubError::OAuthExpired => "oauth_expired",
        GitHubError::OAuthAccessDenied => "oauth_access_denied",
        GitHubError::OAuthError { .. } => "oauth_error",
    }
}

#[derive(Debug, Default)]
pub struct ClearReport {
    pub remotely_inactive: usize,
    pub local_only: usize,
    pub retained: usize,
    pub failures: Vec<ClearFailure>,
}

pub fn run_clear(args: &GhstCli, _cmd: &ClearCmd) -> Result<(), CmdError> {
    let config = load_config(args.config.as_deref())?;
    let cache_dir = Config::cache_dir()?;
    let mut stdout = io::stdout().lock();
    clear_tokens_to(&GitHubClient::new(), &config, &cache_dir, &mut stdout)
}

pub fn clear_tokens_to<C: RevokeTokenClient, W: Write>(
    client: &C,
    config: &Config,
    cache_dir: &Path,
    writer: &mut W,
) -> Result<(), CmdError> {
    let now = OffsetDateTime::now_utc();
    let report = clear_transaction(cache_dir, |transaction| {
        let mut report = ClearReport::default();
        for index in 0..transaction.entries().len() {
            let label = transaction.entries()[index].label.clone();
            let revocation = match &transaction.entries()[index].state {
                CacheInspectionState::Current(entry) if entry.is_usable_at(now) => {
                    if let Some(app) = app_for_entry(config, entry) {
                        let token = match entry {
                            CacheEntry::Root(value) => &value.access_token,
                            CacheEntry::Derived(value) => &value.access_token,
                        };
                        if let Some(client_secret) = app.github_app.client_secret.as_deref() {
                            match client.delete_token(
                                &app.github_app.client_id,
                                client_secret,
                                token.as_ref(),
                            ) {
                                Ok(()) | Err(GitHubError::Http { status: 404, .. }) => true,
                                Err(source) => {
                                    report.retained += 1;
                                    report.failures.push(ClearFailure::GitHubRevocation {
                                        entry: label,
                                        source,
                                    });
                                    continue;
                                }
                            }
                        } else {
                            report.failures.push(ClearFailure::ClientSecretUnavailable {
                                entry: label.clone(),
                            });
                            false
                        }
                    } else {
                        report.failures.push(ClearFailure::MissingAppCredentials {
                            entry: label.clone(),
                        });
                        false
                    }
                }
                CacheInspectionState::Current(_)
                | CacheInspectionState::Unsupported(_)
                | CacheInspectionState::Invalid => false,
            };
            match transaction.delete(index) {
                Ok(true) if revocation => report.remotely_inactive += 1,
                Ok(true) => report.local_only += 1,
                Ok(false) => report.failures.push(ClearFailure::CacheDeletion {
                    entry: label,
                    source: crate::cache::CacheError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "cache entry disappeared",
                    )),
                }),
                Err(source) => report.failures.push(ClearFailure::CacheDeletion {
                    entry: label,
                    source,
                }),
            }
        }
        report
    })?;
    write_report(writer, &report)?;
    if report.failures.is_empty() {
        Ok(())
    } else {
        Err(CmdError::ClearIncomplete {
            failures: report.failures.len(),
        })
    }
}

fn app_for_entry<'a>(config: &'a Config, entry: &CacheEntry) -> Option<&'a RootProfile> {
    let name = match entry {
        CacheEntry::Root(value) => &value.profile,
        CacheEntry::Derived(value) => &value.source_profile,
    };
    match config.profiles.get(name) {
        Some(ProfileConfig::Root(root)) => Some(root),
        Some(ProfileConfig::Derived(_)) | None => None,
    }
}

fn write_report(writer: &mut impl Write, report: &ClearReport) -> io::Result<()> {
    writeln!(writer, "Cache clear report:")?;
    writeln!(
        writer,
        "  Remotely revoked or already inactive: {}",
        report.remotely_inactive
    )?;
    writeln!(writer, "  Deleted locally only: {}", report.local_only)?;
    writeln!(writer, "  Retained for retry: {}", report.retained)?;
    writeln!(writer, "  Failures: {}", report.failures.len())?;
    for failure in &report.failures {
        match failure {
            ClearFailure::MissingAppCredentials { entry } => writeln!(
                writer,
                "  - {entry}: configured root unavailable; deleted locally and token may remain active remotely"
            )?,
            ClearFailure::ClientSecretUnavailable { entry } => writeln!(
                writer,
                "  - {entry}: client secret unavailable; deleted locally and token may remain active remotely"
            )?,
            ClearFailure::GitHubRevocation { entry, source: _ } => {
                writeln!(writer, "  - {entry}: remote revocation failed")?;
            }
            ClearFailure::CacheDeletion { entry, source } => {
                writeln!(writer, "  - {entry}: local deletion failed: {source}")?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{
        AccessToken, CACHE_SCHEMA_VERSION, RootCacheEntry, TokenExpiry, authority_fingerprint,
        format_rfc3339, list_all_cache_entries, save_cache_entry,
    };
    use crate::cmd::root_cache_key;
    use std::cell::Cell;
    use time::Duration;

    struct MockClient(Cell<usize>);

    impl RevokeTokenClient for MockClient {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            _access_token: &str,
        ) -> Result<(), GitHubError> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
    }

    fn secretless_config() -> Config {
        r#"
version = 1
default_profile = "developer"
[profile.developer]
kind = "root"
github_app.account = "acme"
github_app.client_id = "id"
"#
        .parse()
        .unwrap()
    }

    fn cache_root(cache_dir: &Path, expires_at: OffsetDateTime) {
        let now = OffsetDateTime::now_utc();
        let entry = CacheEntry::Root(RootCacheEntry {
            version: CACHE_SCHEMA_VERSION,
            profile: "developer".into(),
            authority_fingerprint: authority_fingerprint("id", "acme"),
            github_user: "octocat".into(),
            issued_at: format_rfc3339(now),
            expires_at: TokenExpiry::new(expires_at),
            access_token: AccessToken::from("root-token"),
        });
        save_cache_entry(cache_dir, &root_cache_key("developer"), &entry).unwrap();
    }

    #[test]
    fn live_secretless_entry_is_deleted_locally_and_incomplete() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_root(&cache_dir, OffsetDateTime::now_utc() + Duration::hours(1));
        let client = MockClient(Cell::new(0));
        let mut output = Vec::new();
        let error =
            clear_tokens_to(&client, &secretless_config(), &cache_dir, &mut output).unwrap_err();
        assert!(matches!(error, CmdError::ClearIncomplete { failures: 1 }));
        assert_eq!(client.0.get(), 0);
        assert!(list_all_cache_entries(&cache_dir).unwrap().is_empty());
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("client secret unavailable")
        );
    }

    #[test]
    fn expired_secretless_entry_needs_no_remote_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_root(&cache_dir, OffsetDateTime::now_utc() - Duration::hours(1));
        let client = MockClient(Cell::new(0));
        clear_tokens_to(&client, &secretless_config(), &cache_dir, &mut Vec::new()).unwrap();
        assert_eq!(client.0.get(), 0);
        assert!(list_all_cache_entries(&cache_dir).unwrap().is_empty());
    }
}
