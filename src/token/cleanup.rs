use crate::cache::{
    CacheEntry, CacheInspectionState, RunCacheEntry, RunState, claim_abandoned_run,
    claim_released_run, delete_entry_if_unchanged, delete_run_after_cleanup, inspect_cache,
};
use crate::config::{BaseProfile, Config};
use crate::github::GitHubError;
use crate::token::RevokeTokenClient;
use std::path::Path;
use time::OffsetDateTime;

pub struct ReleasedRun {
    pub cache_key: String,
    pub run_id: String,
    pub wrapper_pid: u32,
    pub child_pid: u32,
}

#[derive(Clone, Copy)]
pub enum CleanupScope<'a> {
    ReleasedRun(&'a ReleasedRun),
    Prune,
}

pub enum CleanupFailure {
    InvalidEntry {
        entry: String,
    },
    Configuration {
        entry: String,
    },
    ClientSecretUnavailable {
        entry: String,
    },
    Ownership {
        entry: String,
        source: crate::cache::CacheError,
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

enum CleanupOutcome {
    NoAction,
    ExpiredDeleted,
    RunRevoked,
    ActiveRunSkipped,
}

type CleanupAttempt = Result<CleanupOutcome, CleanupFailure>;

impl std::fmt::Debug for CleanupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEntry { entry } => formatter
                .debug_struct("InvalidEntry")
                .field("entry", entry)
                .finish(),
            Self::Configuration { entry } => formatter
                .debug_struct("Configuration")
                .field("entry", entry)
                .finish(),
            Self::ClientSecretUnavailable { entry } => formatter
                .debug_struct("ClientSecretUnavailable")
                .field("entry", entry)
                .finish(),
            Self::Ownership { entry, source } => formatter
                .debug_struct("Ownership")
                .field("entry", entry)
                .field("source", source)
                .finish(),
            Self::GitHubRevocation { entry, source } => formatter
                .debug_struct("GitHubRevocation")
                .field("entry", entry)
                .field("source_kind", &source.kind())
                .finish(),
            Self::CacheDeletion { entry, source } => formatter
                .debug_struct("CacheDeletion")
                .field("entry", entry)
                .field("source", source)
                .finish(),
        }
    }
}

#[derive(Debug, Default)]
pub struct CleanupReport {
    pub expired_deletions: usize,
    pub revoked_runs: usize,
    pub active_runs_skipped: usize,
    pub retained_entries: usize,
    pub failures: Vec<CleanupFailure>,
}

impl CleanupReport {
    pub const fn is_complete(&self) -> bool {
        self.retained_entries == 0 && self.failures.is_empty()
    }

    fn record(&mut self, attempt: CleanupAttempt) {
        match attempt {
            Ok(CleanupOutcome::NoAction) => {}
            Ok(CleanupOutcome::ExpiredDeleted) => self.expired_deletions += 1,
            Ok(CleanupOutcome::RunRevoked) => self.revoked_runs += 1,
            Ok(CleanupOutcome::ActiveRunSkipped) => self.active_runs_skipped += 1,
            Err(failure) => {
                tracing::debug!(failure = ?failure, "retaining cache entry for inspection or retry");
                self.retained_entries += 1;
                self.failures.push(failure);
            }
        }
    }
}

pub fn cleanup<C: RevokeTokenClient>(
    client: &C,
    config: &Config,
    cache_dir: &Path,
    scope: CleanupScope<'_>,
    now: OffsetDateTime,
) -> Result<CleanupReport, crate::cache::CacheError> {
    match scope {
        CleanupScope::ReleasedRun(released) => {
            tracing::debug!(
                cache_key = released.cache_key,
                run_id = released.run_id,
                wrapper_pid = released.wrapper_pid,
                child_pid = released.child_pid,
                "claiming released run for cleanup"
            );
            let mut report = CleanupReport::default();
            let attempt = match claim_released_run(
                cache_dir,
                &released.cache_key,
                &released.run_id,
                released.wrapper_pid,
                released.child_pid,
            ) {
                Ok(entry) => {
                    tracing::debug!(
                        cache_key = released.cache_key,
                        "released run claimed for cleanup"
                    );
                    cleanup_run_entry(client, config, cache_dir, &released.cache_key, &entry)
                }
                Err(source) => {
                    tracing::debug!(cache_key = released.cache_key, error = %source, "failed to claim released run for cleanup");
                    Err(CleanupFailure::Ownership {
                        entry: released.cache_key.clone(),
                        source,
                    })
                }
            };
            report.record(attempt);
            Ok(report)
        }
        CleanupScope::Prune => prune(client, config, cache_dir, now),
    }
}

pub fn cleanup_marked_run<C: RevokeTokenClient>(
    client: &C,
    config: &Config,
    cache_dir: &Path,
    cache_key: &str,
    entry: &RunCacheEntry,
) -> CleanupReport {
    let mut report = CleanupReport::default();
    let attempt = match entry.state {
        RunState::CleanupPending => cleanup_run_entry(client, config, cache_dir, cache_key, entry),
        RunState::Pending | RunState::Running => Err(CleanupFailure::InvalidEntry {
            entry: cache_key.to_owned(),
        }),
    };
    report.record(attempt);
    report
}

fn prune<C: RevokeTokenClient>(
    client: &C,
    config: &Config,
    cache_dir: &Path,
    now: OffsetDateTime,
) -> Result<CleanupReport, crate::cache::CacheError> {
    let mut report = CleanupReport::default();
    let inspections = inspect_cache(cache_dir)?;
    tracing::debug!(cache_dir = %cache_dir.display(), entries = inspections.len(), "inspecting cache entries for pruning");
    for inspection in inspections {
        let label = inspection.label;
        let attempt = match (inspection.cache_key, inspection.state) {
            (None, _) => {
                tracing::debug!(
                    entry = label,
                    "retaining cache entry with an invalid file name"
                );
                Err(CleanupFailure::InvalidEntry { entry: label })
            }
            (Some(_), CacheInspectionState::Invalid) => {
                tracing::debug!(
                    entry = label,
                    "retaining invalid cache entry for manual inspection"
                );
                Err(CleanupFailure::InvalidEntry { entry: label })
            }
            (Some(cache_key), CacheInspectionState::Current(entry))
                if expiry(&entry).value() <= now =>
            {
                delete_expired_entry(cache_dir, &cache_key, &label, &entry)
            }
            (Some(cache_key), CacheInspectionState::Current(entry)) => {
                cleanup_unexpired_entry(client, config, cache_dir, &cache_key, &label, *entry)
            }
        };
        report.record(attempt);
    }
    Ok(report)
}

fn delete_expired_entry(
    cache_dir: &Path,
    cache_key: &str,
    label: &str,
    entry: &CacheEntry,
) -> CleanupAttempt {
    tracing::debug!(
        entry = label,
        kind = entry.kind_name(),
        "deleting expired cache entry"
    );
    match delete_entry_if_unchanged(cache_dir, cache_key, entry) {
        Ok(true) => {
            tracing::debug!(entry = label, "deleted expired cache entry");
            Ok(CleanupOutcome::ExpiredDeleted)
        }
        Ok(false) => {
            tracing::debug!(
                entry = label,
                "expired cache entry changed or disappeared before deletion"
            );
            Err(CleanupFailure::InvalidEntry {
                entry: label.to_owned(),
            })
        }
        Err(source) => {
            tracing::debug!(entry = label, error = %source, "failed to delete expired cache entry");
            Err(CleanupFailure::CacheDeletion {
                entry: label.to_owned(),
                source,
            })
        }
    }
}

fn cleanup_unexpired_entry<C: RevokeTokenClient>(
    client: &C,
    config: &Config,
    cache_dir: &Path,
    cache_key: &str,
    label: &str,
    entry: CacheEntry,
) -> CleanupAttempt {
    match entry {
        CacheEntry::Base(_) | CacheEntry::Scoped(_) => Ok(CleanupOutcome::NoAction),
        CacheEntry::Run(entry) => {
            cleanup_pruned_run(client, config, cache_dir, cache_key, label, &entry)
        }
    }
}

fn cleanup_pruned_run<C: RevokeTokenClient>(
    client: &C,
    config: &Config,
    cache_dir: &Path,
    cache_key: &str,
    label: &str,
    entry: &RunCacheEntry,
) -> CleanupAttempt {
    match entry.state {
        RunState::CleanupPending => cleanup_run_entry(client, config, cache_dir, cache_key, entry),
        RunState::Pending | RunState::Running
            if pid_is_alive(entry.wrapper_pid) || entry.child_pid.is_some_and(pid_is_alive) =>
        {
            tracing::debug!(entry = label, wrapper_pid = entry.wrapper_pid, child_pid = ?entry.child_pid, "skipping active run during pruning");
            Ok(CleanupOutcome::ActiveRunSkipped)
        }
        RunState::Pending | RunState::Running => {
            tracing::debug!(entry = label, "claiming abandoned run for cleanup");
            match claim_abandoned_run(cache_dir, cache_key, entry) {
                Ok(claimed) => cleanup_run_entry(client, config, cache_dir, cache_key, &claimed),
                Err(source) => {
                    tracing::debug!(entry = label, error = %source, "failed to claim abandoned run for cleanup");
                    Err(CleanupFailure::Ownership {
                        entry: label.to_owned(),
                        source,
                    })
                }
            }
        }
    }
}

fn cleanup_run_entry<C: RevokeTokenClient>(
    client: &C,
    config: &Config,
    cache_dir: &Path,
    cache_key: &str,
    entry: &RunCacheEntry,
) -> CleanupAttempt {
    let label = cache_key.to_owned();
    let Some(base) = validated_base(config, entry) else {
        tracing::debug!(
            cache_key,
            source_profile = entry.source_profile,
            "run token source authority no longer matches configuration"
        );
        return Err(CleanupFailure::Configuration { entry: label });
    };
    let Some(secret) = base.github_app.client_secret.as_deref() else {
        tracing::debug!(
            cache_key,
            source_profile = entry.source_profile,
            "run token cannot be remotely revoked because the source profile has no client secret"
        );
        return Err(CleanupFailure::ClientSecretUnavailable { entry: label });
    };
    match client.delete_token(
        &base.github_app.client_id,
        secret,
        entry.access_token.as_ref(),
    ) {
        Ok(()) => tracing::debug!(cache_key, "run token remotely revoked"),
        Err(source) if source.is_not_found() => {
            tracing::debug!(cache_key, "run token was already inactive on GitHub");
        }
        Err(source) => {
            tracing::debug!(cache_key, error = %source, "failed to revoke run token");
            return Err(CleanupFailure::GitHubRevocation {
                entry: label,
                source,
            });
        }
    }
    match delete_run_after_cleanup(cache_dir, cache_key, entry) {
        Ok(_) => {
            tracing::debug!(cache_key, "deleted run recovery entry after remote cleanup");
            Ok(CleanupOutcome::RunRevoked)
        }
        Err(source) => {
            tracing::debug!(cache_key, error = %source, "failed to delete run recovery entry after remote cleanup");
            Err(CleanupFailure::CacheDeletion {
                entry: label,
                source,
            })
        }
    }
}

fn validated_base<'a>(config: &'a Config, entry: &RunCacheEntry) -> Option<&'a BaseProfile> {
    match super::provenance::for_source(
        config,
        &entry.source_profile,
        &entry.source_authority_fingerprint,
    ) {
        super::provenance::ConfiguredAuthority::Match(base) => Some(base),
        super::provenance::ConfiguredAuthority::Mismatch
        | super::provenance::ConfiguredAuthority::Missing => None,
    }
}

const fn expiry(entry: &CacheEntry) -> crate::cache::TokenExpiry {
    match entry {
        CacheEntry::Base(entry) => entry.expires_at,
        CacheEntry::Scoped(entry) => entry.expires_at,
        CacheEntry::Run(entry) => entry.expires_at,
    }
}

#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    let Ok(raw) = i32::try_from(pid) else {
        return true;
    };
    let Some(pid) = rustix::process::Pid::from_raw(raw) else {
        return true;
    };
    !matches!(
        rustix::process::test_kill_process(pid),
        Err(error) if error == rustix::io::Errno::SRCH
    )
}

#[cfg(not(unix))]
fn pid_is_alive(_pid: u32) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{
        RUN_CACHE_SCHEMA_VERSION, RunState, TokenExpiry, authority_fingerprint,
        compute_run_cache_key, load_cache_entry, save_cache_entry,
    };
    use std::cell::{Cell, RefCell};
    use time::Duration;

    struct MockClient {
        revoked: RefCell<Vec<String>>,
        fail: Cell<bool>,
    }

    impl RevokeTokenClient for MockClient {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            access_token: &str,
        ) -> Result<(), GitHubError> {
            self.revoked.borrow_mut().push(access_token.to_owned());
            if self.fail.get() {
                Err(GitHubError::Http {
                    status: 500,
                    message: "failure".into(),
                })
            } else {
                Ok(())
            }
        }
    }

    fn config() -> Config {
        r#"
version = 1
default_profile = "reader"
[profile.developer]
github_app.account = "acme"
github_app.client_id = "id"
github_app.client_secret = "secret"
[profile.reader]
source = "developer"
repo = "acme/api"
permissions = { contents = "read" }
"#
        .parse()
        .unwrap()
    }

    fn run_entry(
        run_id: &str,
        state: RunState,
        wrapper_pid: u32,
        child_pid: Option<u32>,
        expiry: OffsetDateTime,
    ) -> CacheEntry {
        CacheEntry::Run(RunCacheEntry {
            version: RUN_CACHE_SCHEMA_VERSION,
            run_id: run_id.into(),
            state,
            wrapper_pid,
            child_pid,
            command: "true".into(),
            profile: "reader".into(),
            source_profile: "developer".into(),
            source_authority_fingerprint: authority_fingerprint("id", "acme"),
            github_user: "octocat".into(),
            repo_scope: "acme/api".into(),
            expires_at: TokenExpiry::new(expiry),
            access_token: format!("token-{run_id}").into(),
        })
    }

    fn client() -> MockClient {
        MockClient {
            revoked: RefCell::new(Vec::new()),
            fail: Cell::new(false),
        }
    }

    #[test]
    fn prune_skips_active_runs_and_revokes_abandoned_runs() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        for (id, wrapper) in [
            ("active", std::process::id()),
            ("abandoned", i32::MAX as u32),
        ] {
            save_cache_entry(
                &cache_dir,
                &compute_run_cache_key(id),
                &run_entry(
                    id,
                    RunState::Running,
                    wrapper,
                    Some(i32::MAX as u32),
                    now + Duration::hours(1),
                ),
            )
            .unwrap();
        }
        let client = client();
        let report = cleanup(&client, &config(), &cache_dir, CleanupScope::Prune, now).unwrap();
        assert_eq!(report.active_runs_skipped, 1);
        assert_eq!(report.revoked_runs, 1);
        assert!(report.is_complete());
        assert_eq!(&*client.revoked.borrow(), &["token-abandoned"]);
        assert!(
            load_cache_entry(&cache_dir, &compute_run_cache_key("active"))
                .unwrap()
                .is_some()
        );
        assert!(
            load_cache_entry(&cache_dir, &compute_run_cache_key("abandoned"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn prune_deletes_expired_runs_without_remote_revocation() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        let key = compute_run_cache_key("expired");
        save_cache_entry(
            &cache_dir,
            &key,
            &run_entry(
                "expired",
                RunState::CleanupPending,
                i32::MAX as u32,
                None,
                now - Duration::seconds(1),
            ),
        )
        .unwrap();
        let client = client();
        let report = cleanup(&client, &config(), &cache_dir, CleanupScope::Prune, now).unwrap();
        assert_eq!(report.expired_deletions, 1);
        assert!(client.revoked.borrow().is_empty());
        assert!(load_cache_entry(&cache_dir, &key).unwrap().is_none());
    }

    #[test]
    fn prune_does_not_revoke_with_mismatched_authority() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        let key = compute_run_cache_key("mismatched");
        let mut cached = run_entry(
            "mismatched",
            RunState::Running,
            i32::MAX as u32,
            Some(i32::MAX as u32),
            now + Duration::hours(1),
        );
        let CacheEntry::Run(entry) = &mut cached else {
            unreachable!("run_entry returned a non-run entry")
        };
        entry.source_authority_fingerprint = authority_fingerprint("other-id", "different");
        save_cache_entry(&cache_dir, &key, &cached).unwrap();

        let client = client();
        let report = cleanup(&client, &config(), &cache_dir, CleanupScope::Prune, now).unwrap();

        assert!(client.revoked.borrow().is_empty());
        assert_eq!(report.retained_entries, 1);
        assert!(matches!(
            report.failures.as_slice(),
            [CleanupFailure::Configuration { .. }]
        ));
        assert!(matches!(
            load_cache_entry(&cache_dir, &key).unwrap(),
            Some(CacheEntry::Run(RunCacheEntry {
                state: RunState::CleanupPending,
                ..
            }))
        ));
    }

    #[test]
    fn prune_retains_claimed_abandoned_run_when_remote_revocation_fails() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        let key = compute_run_cache_key("failed-revocation");
        save_cache_entry(
            &cache_dir,
            &key,
            &run_entry(
                "failed-revocation",
                RunState::Running,
                i32::MAX as u32,
                Some(i32::MAX as u32),
                now + Duration::hours(1),
            ),
        )
        .unwrap();
        let client = client();
        client.fail.set(true);

        let report = cleanup(&client, &config(), &cache_dir, CleanupScope::Prune, now).unwrap();

        assert_eq!(report.retained_entries, 1);
        assert!(matches!(
            report.failures.as_slice(),
            [CleanupFailure::GitHubRevocation { .. }]
        ));
        assert_eq!(&*client.revoked.borrow(), &["token-failed-revocation"]);
        assert!(matches!(
            load_cache_entry(&cache_dir, &key).unwrap(),
            Some(CacheEntry::Run(RunCacheEntry {
                state: RunState::CleanupPending,
                ..
            }))
        ));
    }

    #[test]
    fn released_cleanup_requires_ownership_and_retains_network_failures() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        let key = compute_run_cache_key("released");
        save_cache_entry(
            &cache_dir,
            &key,
            &run_entry(
                "released",
                RunState::Running,
                100,
                Some(200),
                now + Duration::hours(1),
            ),
        )
        .unwrap();
        let client = client();
        let wrong = cleanup(
            &client,
            &config(),
            &cache_dir,
            CleanupScope::ReleasedRun(&ReleasedRun {
                cache_key: key.clone(),
                run_id: "released".into(),
                wrapper_pid: 100,
                child_pid: 201,
            }),
            now,
        )
        .unwrap();
        assert!(!wrong.is_complete());
        client.fail.set(true);
        let failed = cleanup(
            &client,
            &config(),
            &cache_dir,
            CleanupScope::ReleasedRun(&ReleasedRun {
                cache_key: key.clone(),
                run_id: "released".into(),
                wrapper_pid: 100,
                child_pid: 200,
            }),
            now,
        )
        .unwrap();
        assert!(!failed.is_complete());
        let CacheEntry::Run(retained) = load_cache_entry(&cache_dir, &key).unwrap().unwrap() else {
            panic!("expected retained run")
        };
        assert_eq!(retained.state, RunState::CleanupPending);
    }
}
