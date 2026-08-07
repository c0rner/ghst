use crate::cache::{CacheEntry, CacheInspectionState, revoke_transaction};
use crate::config::{Config, ProfileConfig, RootProfile};
use crate::github::{GitHubError, RevokeTokenClient};
use std::path::Path;
use time::OffsetDateTime;

pub enum RevokeFailure {
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
        for index in 0..transaction.entries().len() {
            let label = transaction.entries()[index].label.clone();
            let revocation = match &transaction.entries()[index].state {
                CacheInspectionState::Current(entry) if entry.is_usable_at(now) => {
                    if let Some(app) = app_for_entry(config, entry) {
                        if let Some(secret) = app.github_app.client_secret.as_deref() {
                            match client.delete_token(
                                &app.github_app.client_id,
                                secret,
                                entry.access_token().as_ref(),
                            ) {
                                Ok(()) => true,
                                Err(source) if source.is_not_found() => true,
                                Err(source) => {
                                    report.retained += 1;
                                    report.failures.push(RevokeFailure::GitHubRevocation {
                                        entry: label,
                                        source,
                                    });
                                    continue;
                                }
                            }
                        } else {
                            report
                                .failures
                                .push(RevokeFailure::ClientSecretUnavailable {
                                    entry: label.clone(),
                                });
                            false
                        }
                    } else {
                        report.failures.push(RevokeFailure::MissingAppCredentials {
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
                Ok(false) => report.failures.push(RevokeFailure::CacheDeletion {
                    entry: label,
                    source: crate::cache::CacheError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "cache entry disappeared",
                    )),
                }),
                Err(source) => report.failures.push(RevokeFailure::CacheDeletion {
                    entry: label,
                    source,
                }),
            }
        }
        report
    })
}

fn app_for_entry<'a>(config: &'a Config, entry: &CacheEntry) -> Option<&'a RootProfile> {
    let name = match entry {
        CacheEntry::Root(value) => &value.profile,
        CacheEntry::Derived(value) => &value.source_profile,
        CacheEntry::Run(value) => &value.source_profile,
    };
    match config.profiles.get(name) {
        Some(ProfileConfig::Root(root)) => match entry {
            CacheEntry::Run(entry)
                if crate::cache::authority_fingerprint(
                    &root.github_app.client_id,
                    &root.github_app.account,
                ) != entry.source_authority_fingerprint =>
            {
                None
            }
            CacheEntry::Root(_) | CacheEntry::Derived(_) | CacheEntry::Run(_) => Some(root),
        },
        Some(ProfileConfig::Derived(_)) | None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{
        AccessToken, CACHE_SCHEMA_VERSION, RootCacheEntry, TokenExpiry, authority_fingerprint,
        format_rfc3339, list_all_cache_entries, save_cache_entry,
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
            issued_at: format_rfc3339(OffsetDateTime::now_utc()),
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
}
