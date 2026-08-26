use crate::cache::{CacheInspectionState, revoke_transaction};
use crate::config::Config;
use crate::github::GitHubError;
use crate::token::RevokeTokenClient;
use std::path::Path;
use time::OffsetDateTime;

pub enum RevokeFailure {
    MissingAppCredentials {
        entry: String,
    },
    ClientSecretUnavailable {
        entry: String,
    },
    AuthorityMismatch {
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

impl std::fmt::Debug for RevokeFailure {
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
            Self::AuthorityMismatch { entry } => formatter
                .debug_struct("AuthorityMismatch")
                .field("entry", entry)
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
pub struct RevokeReport {
    pub remotely_inactive: usize,
    pub local_only: usize,
    pub retained: usize,
    pub failures: Vec<RevokeFailure>,
}

pub fn revoke_all<C: RevokeTokenClient>(
    client: &C,
    config: &Config,
    cache_dir: &Path,
    now: OffsetDateTime,
) -> Result<RevokeReport, crate::cache::CacheError> {
    revoke_transaction(cache_dir, |transaction| {
        let mut report = RevokeReport::default();
        tracing::debug!(cache_dir = %cache_dir.display(), entries = transaction.entries().len(), "started cache-wide credential revocation transaction");
        for index in 0..transaction.entries().len() {
            let label = transaction.entries()[index].label.clone();
            tracing::debug!(entry = label, "processing cached credential for revocation");
            let Some(revocation) = attempt_remote_revocation(
                client,
                config,
                &transaction.entries()[index].state,
                &label,
                now,
                &mut report,
            ) else {
                continue;
            };
            match transaction.delete(index) {
                Ok(true) if revocation => {
                    report.remotely_inactive += 1;
                    tracing::debug!(
                        entry = label,
                        "deleted remotely inactive credential from local cache"
                    );
                }
                Ok(true) => {
                    report.local_only += 1;
                    tracing::debug!(entry = label, "deleted credential from local cache only");
                }
                Ok(false) => report.failures.push(RevokeFailure::CacheDeletion {
                    entry: label,
                    source: crate::cache::CacheError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "cache entry disappeared",
                    )),
                }),
                Err(source) => {
                    tracing::debug!(entry = label, error = %source, "failed to delete credential from local cache");
                    report.failures.push(RevokeFailure::CacheDeletion {
                        entry: label,
                        source,
                    });
                }
            }
        }
        report
    })
}

fn attempt_remote_revocation<C: RevokeTokenClient>(
    client: &C,
    config: &Config,
    state: &CacheInspectionState,
    label: &str,
    now: OffsetDateTime,
    report: &mut RevokeReport,
) -> Option<bool> {
    let CacheInspectionState::Current(entry) = state else {
        tracing::debug!(
            entry = label,
            "cache entry is invalid; deleting locally without remote revocation"
        );
        return Some(false);
    };
    if !entry.is_safe_to_handoff_at(now) {
        tracing::debug!(
            entry = label,
            "cached credential is expired or inside the handoff margin; deleting locally without remote revocation"
        );
        return Some(false);
    }
    match super::provenance::for_entry(config, entry) {
        super::provenance::ConfiguredAuthority::Match(app) => {
            let Some(secret) = app.github_app.client_secret.as_deref() else {
                tracing::debug!(
                    entry = label,
                    "client secret unavailable; deleting cached credential locally only"
                );
                report
                    .failures
                    .push(RevokeFailure::ClientSecretUnavailable {
                        entry: label.to_owned(),
                    });
                return Some(false);
            };
            match client.delete_token(
                &app.github_app.client_id,
                secret,
                entry.access_token().as_ref(),
            ) {
                Ok(()) => {
                    tracing::debug!(entry = label, "cached credential remotely revoked");
                    Some(true)
                }
                Err(source) if source.is_not_found() => {
                    tracing::debug!(
                        entry = label,
                        "cached credential was already inactive on GitHub"
                    );
                    Some(true)
                }
                Err(source) => {
                    tracing::debug!(entry = label, error = %source, "failed to remotely revoke cached credential; retaining it for retry");
                    report.retained += 1;
                    report.failures.push(RevokeFailure::GitHubRevocation {
                        entry: label.to_owned(),
                        source,
                    });
                    None
                }
            }
        }
        super::provenance::ConfiguredAuthority::Mismatch => {
            tracing::debug!(
                entry = label,
                "cached credential authority differs from configuration; deleting locally only"
            );
            report.failures.push(RevokeFailure::AuthorityMismatch {
                entry: label.to_owned(),
            });
            Some(false)
        }
        super::provenance::ConfiguredAuthority::Missing => {
            tracing::debug!(
                entry = label,
                "cached credential source profile is missing; deleting locally only"
            );
            report.failures.push(RevokeFailure::MissingAppCredentials {
                entry: label.to_owned(),
            });
            Some(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{
        AccessToken, CACHE_SCHEMA_VERSION, CacheEntry, DerivedCacheEntry, RUN_CACHE_SCHEMA_VERSION,
        RootCacheEntry, RunCacheEntry, RunState, TokenExpiry, authority_fingerprint,
        compute_cache_key, compute_run_cache_key, list_all_cache_entries, save_cache_entry,
    };
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

    fn config(secret: bool) -> Config {
        let secret = if secret {
            "github_app.client_secret = \"secret\""
        } else {
            ""
        };
        format!(
            "version = 1\ndefault_profile = \"developer\"\n[profile.developer]\ngithub_app.account = \"acme\"\ngithub_app.client_id = \"id\"\n{secret}\n"
        )
        .parse()
        .unwrap()
    }

    fn cache_root(cache_dir: &Path, expiry: OffsetDateTime) {
        let entry = CacheEntry::Root(RootCacheEntry {
            version: CACHE_SCHEMA_VERSION,
            profile: "developer".into(),
            authority_fingerprint: authority_fingerprint("id", "acme"),
            github_user: "octocat".into(),
            expires_at: TokenExpiry::new(expiry),
            access_token: AccessToken::from("root-token"),
        });
        save_cache_entry(
            cache_dir,
            &crate::token::root_cache_key("developer"),
            &entry,
        )
        .unwrap();
    }

    #[test]
    fn live_secretless_entry_is_local_only_and_incomplete() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_root(&cache_dir, OffsetDateTime::now_utc() + Duration::hours(1));
        let client = MockClient(Cell::new(0));
        let report = revoke_all(
            &client,
            &config(false),
            &cache_dir,
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        assert_eq!(report.local_only, 1);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(client.0.get(), 0);
        assert!(list_all_cache_entries(&cache_dir).unwrap().is_empty());
    }

    #[test]
    fn live_entry_is_revoked_and_expired_entry_is_deleted_locally() {
        for (offset, remote) in [(Duration::hours(1), 1), (Duration::hours(-1), 0)] {
            let temp = tempfile::tempdir().unwrap();
            let cache_dir = temp.path().join("cache");
            cache_root(&cache_dir, OffsetDateTime::now_utc() + offset);
            let client = MockClient(Cell::new(0));
            let report = revoke_all(
                &client,
                &config(true),
                &cache_dir,
                OffsetDateTime::now_utc(),
            )
            .unwrap();
            assert_eq!(client.0.get(), remote);
            assert!(report.failures.is_empty());
            assert!(list_all_cache_entries(&cache_dir).unwrap().is_empty());
        }
    }

    #[test]
    fn authority_mismatch_is_local_only_for_every_cache_kind() {
        let now = OffsetDateTime::now_utc();
        let changed: Config = "version = 1\ndefault_profile = \"developer\"\n[profile.developer]\ngithub_app.account = \"different\"\ngithub_app.client_id = \"other-id\"\ngithub_app.client_secret = \"secret\"\n"
            .parse()
            .unwrap();
        for (key, entry) in mismatched_entries(now + Duration::hours(1)) {
            let temp = tempfile::tempdir().unwrap();
            let cache_dir = temp.path().join("cache");
            save_cache_entry(&cache_dir, &key, &entry).unwrap();
            let client = MockClient(Cell::new(0));
            let report = revoke_all(&client, &changed, &cache_dir, now).unwrap();
            assert_eq!(client.0.get(), 0);
            assert_eq!(report.remotely_inactive, 0);
            assert_eq!(report.local_only, 1);
            assert!(matches!(
                report.failures.as_slice(),
                [RevokeFailure::AuthorityMismatch { .. }]
            ));
            assert!(list_all_cache_entries(&cache_dir).unwrap().is_empty());
        }
    }

    fn mismatched_entries(expiry: OffsetDateTime) -> [(String, crate::cache::CacheEntry); 3] {
        let authority = authority_fingerprint("id", "acme");
        [
            (
                crate::token::root_cache_key("developer"),
                crate::cache::CacheEntry::Root(RootCacheEntry {
                    version: CACHE_SCHEMA_VERSION,
                    profile: "developer".into(),
                    authority_fingerprint: authority.clone(),
                    github_user: "octocat".into(),
                    expires_at: TokenExpiry::new(expiry),
                    access_token: AccessToken::from("root-token"),
                }),
            ),
            (
                compute_cache_key("reader", "acme/api"),
                crate::cache::CacheEntry::Derived(DerivedCacheEntry {
                    version: CACHE_SCHEMA_VERSION,
                    profile: "reader".into(),
                    source_profile: "developer".into(),
                    source_authority_fingerprint: authority.clone(),
                    parent_generation: "generation".into(),
                    policy_fingerprint: "policy".into(),
                    github_user: "octocat".into(),
                    repo_scope: "acme/api".into(),
                    expires_at: TokenExpiry::new(expiry),
                    access_token: AccessToken::from("derived-token"),
                }),
            ),
            (
                compute_run_cache_key("run-1"),
                crate::cache::CacheEntry::Run(RunCacheEntry {
                    version: RUN_CACHE_SCHEMA_VERSION,
                    run_id: "run-1".into(),
                    state: RunState::Running,
                    wrapper_pid: 100,
                    child_pid: Some(101),
                    command: "true".into(),
                    profile: "reader".into(),
                    source_profile: "developer".into(),
                    source_authority_fingerprint: authority,
                    github_user: "octocat".into(),
                    repo_scope: "acme/api".into(),
                    expires_at: TokenExpiry::new(expiry),
                    access_token: AccessToken::from("run-token"),
                }),
            ),
        ]
    }
}
