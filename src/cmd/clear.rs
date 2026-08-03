use crate::cache::{CacheEntry, CacheInspectionState, clear_transaction};
use crate::cmd::{ClearCmd, CmdError, GhstCli, load_config};
use crate::config::{Config, ProfileConfig, RootProfile};
use crate::github::{GitHubClient, GitHubError, RevokeTokenClient};
use std::io::{self, Write};
use std::path::Path;
use time::OffsetDateTime;
use tracing::info;

pub enum ClearFailure {
    MissingAppCredentials {
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
    info!("Command: clear");
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
                        match client.delete_token(
                            &app.github_app.client_id,
                            &app.github_app.client_secret,
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
                "  - {entry}: App credentials unavailable; deleted locally"
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
