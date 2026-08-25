use super::*;
use crate::cache::{
    CACHE_SCHEMA_VERSION, CacheEntry, RootCacheEntry, TokenExpiry, authority_fingerprint,
    cache_epoch, compute_cache_key, delete_cache_entry, load_cache_entry, save_cache_entry,
};
use crate::config::{Config, GitHubAppConfig, ProfileConfig};
use crate::github::GitHubError;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;
use time::{Duration, OffsetDateTime};

const CONFIG: &str = r#"
version = 1
default_profile = "reader"

[profile.developer]
github_app.account = "acme"
github_app.client_id = "id"
github_app.client_secret = "secret"

[profile.reader]
source = "developer"
repo = "acme/api"
permissions = { contents = "read", pull_requests = "write" }
"#;

struct MockClient {
    scoped: RefCell<Option<Result<IssuedScopedToken, GitHubError>>>,
    request: RefCell<Option<serde_json::Value>>,
    revoked: RefCell<Vec<String>>,
    revoke_fails: bool,
}

impl RevokeTokenClient for MockClient {
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

impl RootTokenClient for MockClient {
    fn get_user(&self, _access_token: &str) -> Result<GitHubUser, GitHubError> {
        Ok(GitHubUser {
            login: "octocat".into(),
        })
    }
}

impl ScopedTokenClient for MockClient {
    fn create_scoped_token(
        &self,
        request: &ScopedTokenRequest<'_>,
    ) -> Result<IssuedScopedToken, GitHubError> {
        self.request.replace(Some(serde_json::json!({
            "client_id": request.client_id,
            "client_secret": request.client_secret,
            "root_token": request.root_token,
            "target": request.target,
            "repositories": request.repositories,
            "permissions": request.permissions,
        })));
        self.scoped.borrow_mut().take().unwrap()
    }
}

fn client(response: IssuedScopedToken) -> MockClient {
    MockClient {
        scoped: RefCell::new(Some(Ok(response))),
        request: RefCell::new(None),
        revoked: RefCell::new(Vec::new()),
        revoke_fails: false,
    }
}

fn cache_root(cache_dir: &Path, now: OffsetDateTime, token: &str) {
    let entry = CacheEntry::Root(RootCacheEntry {
        version: CACHE_SCHEMA_VERSION,
        profile: "developer".into(),
        authority_fingerprint: authority_fingerprint("id", "acme"),
        github_user: "octocat".into(),
        expires_at: TokenExpiry::new(now + Duration::hours(2)),
        access_token: token.into(),
    });
    save_cache_entry(cache_dir, &root_cache_key("developer"), &entry).unwrap();
}

fn cache_derived(cache_dir: &Path, expiry: OffsetDateTime, token: &str) -> String {
    let root_key = root_cache_key("developer");
    let CacheEntry::Root(root) = load_cache_entry(cache_dir, &root_key).unwrap().unwrap() else {
        panic!("expected root")
    };
    let permissions = BTreeMap::from([
        ("contents".to_owned(), "read".to_owned()),
        ("pull_requests".to_owned(), "write".to_owned()),
    ]);
    let cache_key = compute_cache_key("reader", "acme/api");
    let entry = CacheEntry::Derived(crate::cache::DerivedCacheEntry {
        version: CACHE_SCHEMA_VERSION,
        profile: "reader".into(),
        source_profile: "developer".into(),
        source_authority_fingerprint: authority_fingerprint("id", "acme"),
        parent_generation: root.generation_fingerprint(),
        policy_fingerprint: crate::cache::policy_fingerprint("acme", "acme/api", &permissions),
        github_user: "octocat".into(),
        repo_scope: "acme/api".into(),
        expires_at: TokenExpiry::new(expiry),
        access_token: token.into(),
    });
    save_cache_entry(cache_dir, &cache_key, &entry).unwrap();
    cache_key
}

fn no_response_client() -> MockClient {
    MockClient {
        scoped: RefCell::new(None),
        request: RefCell::new(None),
        revoked: RefCell::new(Vec::new()),
        revoke_fails: false,
    }
}

fn failing_scoped_client(status: u16) -> MockClient {
    MockClient {
        scoped: RefCell::new(Some(Err(GitHubError::Http {
            status,
            message: "request rejected".into(),
        }))),
        request: RefCell::new(None),
        revoked: RefCell::new(Vec::new()),
        revoke_fails: false,
    }
}

#[test]
fn root_lifetime_requires_a_representable_value_beyond_the_margin() {
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000)
        .unwrap()
        .replace_nanosecond(500_000_000)
        .unwrap();
    for value in [None, Some(0), Some(30), Some(u64::MAX)] {
        assert!(matches!(
            validate_root_expiry(value, now),
            Err(TokenError::InvalidLifetime { .. })
        ));
    }
    let lifetime = 24 * 60 * 60;
    let expiry = validate_root_expiry(Some(lifetime), now).unwrap().value();
    assert_eq!(expiry.nanosecond(), 0);
    assert_eq!(
        expiry,
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap() + Duration::hours(24)
    );
}

#[test]
fn scoped_lifetime_requires_a_valid_timestamp_beyond_the_margin() {
    let now = OffsetDateTime::now_utc();
    for value in [
        Some("not-a-timestamp".to_owned()),
        Some(TokenExpiry::new(now + Duration::seconds(30)).to_string()),
    ] {
        assert!(matches!(
            validate_scoped_expiry(value.as_deref(), now),
            Err(TokenError::InvalidLifetime { .. })
        ));
    }
    let expiry = TokenExpiry::new(now + Duration::hours(24));
    assert_eq!(
        validate_scoped_expiry(Some(&expiry.to_string()), now).unwrap(),
        expiry
    );
}

#[test]
fn response_receipt_time_rejects_latency_crossing_the_handoff_margin() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_root(&cache_dir, now, "root-token");
    let client = client(IssuedScopedToken {
        access_token: "too-late".into(),
        expires_at: Some(TokenExpiry::new(now + Duration::seconds(40)).to_string()),
    });
    let config: Config = CONFIG.parse().unwrap();
    let mut times = [now, now, now + Duration::seconds(15)].into_iter();

    let result = super::acquire::acquire_with_clock(
        &client,
        &AcquireRequest {
            config: &config,
            cache_dir: &cache_dir,
            profile_name: "reader",
            repositories: &[],
        },
        || panic!("auto not expected"),
        || times.next().unwrap(),
    );

    assert!(matches!(result, Err(TokenError::InvalidLifetime { .. })));
    assert_eq!(&*client.revoked.borrow(), &["too-late"]);
}

#[test]
fn root_authority_and_kind_are_validated() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_root(&cache_dir, now, "root");
    let config: Config = CONFIG.parse().unwrap();
    let ProfileConfig::Root(root) = config.profiles.get("developer").unwrap() else {
        panic!("expected root");
    };
    assert!(
        load_current_root_entry(&cache_dir, "developer", &root.github_app)
            .unwrap()
            .is_some()
    );
    let mismatched = GitHubAppConfig {
        account: "other".into(),
        client_id: "id".into(),
        client_secret: None,
    };
    assert!(
        load_current_root_entry(&cache_dir, "developer", &mismatched)
            .unwrap()
            .is_none()
    );
}

#[test]
fn root_acquisition_returns_cached_token_and_rejects_repository_scope() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_root(&cache_dir, now, "root-token");
    let config: Config = CONFIG.parse().unwrap();
    let client = client(IssuedScopedToken {
        access_token: "unused".into(),
        expires_at: None,
    });
    let acquired = acquire(
        &client,
        &AcquireRequest {
            config: &config,
            cache_dir: &cache_dir,
            profile_name: "developer",
            repositories: &[],
        },
        || panic!("auto not expected"),
    )
    .unwrap();
    assert_eq!(acquired.access_token.as_ref(), "root-token");
    assert_eq!(acquired.repo_scope, "all");

    assert!(matches!(
        acquire(
            &client,
            &AcquireRequest {
                config: &config,
                cache_dir: &cache_dir,
                profile_name: "developer",
                repositories: &["acme/api".into()],
            },
            || panic!("auto not expected"),
        ),
        Err(TokenError::RootScopeRejected(profile)) if profile == "developer"
    ));
}

#[test]
fn invalid_root_response_is_revoked_and_not_persisted() {
    let config: Config = CONFIG.parse().unwrap();
    let ProfileConfig::Root(root) = config.profiles.get("developer").unwrap() else {
        panic!("expected root");
    };
    let client = client(IssuedScopedToken {
        access_token: "unused".into(),
        expires_at: None,
    });
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let response = IssuedRootToken {
        access_token: "bad-root".into(),
        expires_in: None,
    };
    assert!(matches!(
        persist_root_response(
            &client,
            root,
            "developer",
            &cache_dir,
            response,
            OffsetDateTime::now_utc(),
            cache_epoch(&cache_dir).unwrap(),
        ),
        Err(TokenError::InvalidLifetime { .. })
    ));
    assert_eq!(&*client.revoked.borrow(), &["bad-root"]);
    assert!(
        load_cache_entry(&cache_dir, &root_cache_key("developer"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn derived_acquisition_sends_exact_narrowing_request() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_root(&cache_dir, now, "root-token");
    let exact_expiry = TokenExpiry::new(now + Duration::hours(6));
    let client = client(IssuedScopedToken {
        access_token: "child-token".into(),
        expires_at: Some(exact_expiry.to_string()),
    });
    let config: Config = CONFIG
        .replace(
            "repo = \"acme/api\"",
            "repo = [\"acme/web\", \"ACME/api\", \"acme/web\"]",
        )
        .parse()
        .unwrap();
    let acquired = acquire(
        &client,
        &AcquireRequest {
            config: &config,
            cache_dir: &cache_dir,
            profile_name: "reader",
            repositories: &[],
        },
        || panic!("auto not expected"),
    )
    .unwrap();
    assert_eq!(acquired.access_token.as_ref(), "child-token");
    assert_eq!(acquired.expires_at, exact_expiry);
    assert_eq!(acquired.repo_scope, "acme/api,acme/web");
    assert_eq!(
        client.request.borrow().as_ref().unwrap(),
        &serde_json::json!({
            "client_id": "id",
            "client_secret": "secret",
            "root_token": "root-token",
            "target": "acme",
            "repositories": ["api", "web"],
            "permissions": {"contents": "read", "pull_requests": "write"},
        })
    );
    let CacheEntry::Derived(cached) = load_cache_entry(
        &cache_dir,
        &compute_cache_key("reader", "acme/api,acme/web"),
    )
    .unwrap()
    .unwrap() else {
        panic!("expected derived entry")
    };
    assert_eq!(cached.expires_at, exact_expiry);
}

#[test]
fn permanent_scoped_rejection_evicts_the_rejected_root() {
    let config: Config = CONFIG.parse().unwrap();
    for status in [401, 404] {
        let now = OffsetDateTime::now_utc();
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_root(&cache_dir, now, "rejected-root");
        let result = acquire(
            &failing_scoped_client(status),
            &AcquireRequest {
                config: &config,
                cache_dir: &cache_dir,
                profile_name: "reader",
                repositories: &[],
            },
            || panic!("auto not expected"),
        );

        assert!(
            matches!(result, Err(TokenError::NoSourceTokenCached(profile)) if profile == "developer")
        );
        assert!(
            load_cache_entry(&cache_dir, &root_cache_key("developer"))
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn scoped_policy_and_transient_rejections_retain_the_root() {
    let config: Config = CONFIG.parse().unwrap();
    for status in [403, 500] {
        let now = OffsetDateTime::now_utc();
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_root(&cache_dir, now, "retained-root");
        let result = acquire(
            &failing_scoped_client(status),
            &AcquireRequest {
                config: &config,
                cache_dir: &cache_dir,
                profile_name: "reader",
                repositories: &[],
            },
            || panic!("auto not expected"),
        );

        match status {
            403 => assert!(matches!(
                result,
                Err(TokenError::ScopedTokenForbidden { .. })
            )),
            500 => assert!(matches!(
                result,
                Err(TokenError::GitHub(GitHubError::Http { status: 500, .. }))
            )),
            _ => unreachable!("test status is fixed"),
        }
        assert_eq!(
            load_cache_entry(&cache_dir, &root_cache_key("developer"))
                .unwrap()
                .unwrap()
                .access_token()
                .as_ref(),
            "retained-root"
        );
    }
}

#[test]
fn invalid_scoped_response_is_revoked_without_cache_entry() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_root(&cache_dir, now, "root-token");
    let client = client(IssuedScopedToken {
        access_token: "bad-child".into(),
        expires_at: None,
    });
    let config: Config = CONFIG.parse().unwrap();
    assert!(matches!(
        acquire(
            &client,
            &AcquireRequest {
                config: &config,
                cache_dir: &cache_dir,
                profile_name: "reader",
                repositories: &[],
            },
            || panic!("auto not expected"),
        ),
        Err(TokenError::InvalidLifetime { .. })
    ));
    assert_eq!(&*client.revoked.borrow(), &["bad-child"]);
    assert!(
        load_cache_entry(&cache_dir, &compute_cache_key("reader", "acme/api"))
            .unwrap()
            .is_none()
    );
}

struct GenerationChangingClient<'a> {
    cache_dir: &'a Path,
    now: OffsetDateTime,
    revoked: RefCell<Vec<String>>,
}

struct RejectingGenerationChangingClient<'a> {
    cache_dir: &'a Path,
    now: OffsetDateTime,
}

impl RevokeTokenClient for RejectingGenerationChangingClient<'_> {
    fn delete_token(
        &self,
        _client_id: &str,
        _client_secret: &str,
        _access_token: &str,
    ) -> Result<(), GitHubError> {
        Ok(())
    }
}

impl ScopedTokenClient for RejectingGenerationChangingClient<'_> {
    fn create_scoped_token(
        &self,
        _request: &ScopedTokenRequest<'_>,
    ) -> Result<IssuedScopedToken, GitHubError> {
        let key = root_cache_key("developer");
        delete_cache_entry(self.cache_dir, &key).unwrap();
        cache_root(self.cache_dir, self.now, "replacement-root");
        Err(GitHubError::Http {
            status: 401,
            message: "rejected old root".into(),
        })
    }
}

#[test]
fn permanent_rejection_preserves_a_concurrent_root_replacement() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_root(&cache_dir, now, "rejected-root");
    let client = RejectingGenerationChangingClient {
        cache_dir: &cache_dir,
        now,
    };
    let config: Config = CONFIG.parse().unwrap();

    let result = acquire(
        &client,
        &AcquireRequest {
            config: &config,
            cache_dir: &cache_dir,
            profile_name: "reader",
            repositories: &[],
        },
        || panic!("auto not expected"),
    );

    assert!(
        matches!(result, Err(TokenError::RootGenerationChanged(profile)) if profile == "developer")
    );
    assert_eq!(
        load_cache_entry(&cache_dir, &root_cache_key("developer"))
            .unwrap()
            .unwrap()
            .access_token()
            .as_ref(),
        "replacement-root"
    );
}

impl RevokeTokenClient for GenerationChangingClient<'_> {
    fn delete_token(
        &self,
        _client_id: &str,
        _client_secret: &str,
        access_token: &str,
    ) -> Result<(), GitHubError> {
        self.revoked.borrow_mut().push(access_token.to_owned());
        Ok(())
    }
}

impl ScopedTokenClient for GenerationChangingClient<'_> {
    fn create_scoped_token(
        &self,
        _request: &ScopedTokenRequest<'_>,
    ) -> Result<IssuedScopedToken, GitHubError> {
        let key = root_cache_key("developer");
        delete_cache_entry(self.cache_dir, &key).unwrap();
        cache_root(self.cache_dir, self.now, "replacement-root");
        Ok(IssuedScopedToken {
            access_token: "orphaned-child".into(),
            expires_at: Some(
                TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(1)).to_string(),
            ),
        })
    }
}

#[test]
fn root_generation_change_revokes_candidate_and_requests_retry() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_root(&cache_dir, now, "root-token");
    let client = GenerationChangingClient {
        cache_dir: &cache_dir,
        now,
        revoked: RefCell::new(Vec::new()),
    };
    let config: Config = CONFIG.parse().unwrap();
    assert!(matches!(
        acquire(
            &client,
            &AcquireRequest {
                config: &config,
                cache_dir: &cache_dir,
                profile_name: "reader",
                repositories: &[],
            },
            || panic!("auto not expected"),
        ),
        Err(TokenError::RootGenerationChanged(profile)) if profile == "developer"
    ));
    assert_eq!(&*client.revoked.borrow(), &["orphaned-child"]);
}

#[test]
fn cached_derived_token_remains_usable_after_root_expiry() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_root(&cache_dir, now, "root-token");
    let config: Config = CONFIG.parse().unwrap();
    let first_client = client(IssuedScopedToken {
        access_token: "child-token".into(),
        expires_at: Some(
            TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(6)).to_string(),
        ),
    });
    let request = AcquireRequest {
        config: &config,
        cache_dir: &cache_dir,
        profile_name: "reader",
        repositories: &[],
    };
    acquire(&first_client, &request, || panic!("auto not expected")).unwrap();

    let root_key = root_cache_key("developer");
    let CacheEntry::Root(mut root) = load_cache_entry(&cache_dir, &root_key).unwrap().unwrap()
    else {
        panic!("expected root");
    };
    delete_cache_entry(&cache_dir, &root_key).unwrap();
    root.expires_at = TokenExpiry::new(now - Duration::minutes(1));
    save_cache_entry(&cache_dir, &root_key, &CacheEntry::Root(root)).unwrap();

    let unused_client = MockClient {
        scoped: RefCell::new(None),
        request: RefCell::new(None),
        revoked: RefCell::new(Vec::new()),
        revoke_fails: false,
    };
    let acquired = acquire(&unused_client, &request, || panic!("auto not expected")).unwrap();
    assert_eq!(acquired.access_token.as_ref(), "child-token");
    assert!(unused_client.request.borrow().is_none());
}

#[test]
fn renewable_derived_token_is_replaced_and_displaced_token_is_revoked() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_root(&cache_dir, now, "root-token");
    let cache_key = cache_derived(&cache_dir, now + Duration::minutes(5), "renewable-child");
    let exact_expiry = TokenExpiry::new(now + Duration::hours(1));
    let client = client(IssuedScopedToken {
        access_token: "renewed-child".into(),
        expires_at: Some(exact_expiry.to_string()),
    });
    let config: Config = CONFIG.parse().unwrap();
    let mut times = [now, now, now].into_iter();

    let acquired = super::acquire::acquire_with_clock(
        &client,
        &AcquireRequest {
            config: &config,
            cache_dir: &cache_dir,
            profile_name: "reader",
            repositories: &[],
        },
        || panic!("auto not expected"),
        || times.next().unwrap(),
    )
    .unwrap();

    assert_eq!(acquired.access_token.as_ref(), "renewed-child");
    assert_eq!(&*client.revoked.borrow(), &["renewable-child"]);
    let CacheEntry::Derived(cached) = load_cache_entry(&cache_dir, &cache_key).unwrap().unwrap()
    else {
        panic!("expected derived entry")
    };
    assert_eq!(cached.access_token.as_ref(), "renewed-child");
    assert_eq!(cached.expires_at, exact_expiry);
}

#[test]
fn renewable_derived_token_falls_back_when_root_is_not_usable() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_root(&cache_dir, now, "root-token");
    cache_derived(&cache_dir, now + Duration::minutes(5), "renewable-child");
    let root_key = root_cache_key("developer");
    let CacheEntry::Root(mut root) = load_cache_entry(&cache_dir, &root_key).unwrap().unwrap()
    else {
        panic!("expected root")
    };
    delete_cache_entry(&cache_dir, &root_key).unwrap();
    root.expires_at = TokenExpiry::new(now + Duration::seconds(30));
    save_cache_entry(&cache_dir, &root_key, &CacheEntry::Root(root)).unwrap();
    let client = no_response_client();
    let config: Config = CONFIG.parse().unwrap();
    let mut times = [now, now].into_iter();

    let acquired = super::acquire::acquire_with_clock(
        &client,
        &AcquireRequest {
            config: &config,
            cache_dir: &cache_dir,
            profile_name: "reader",
            repositories: &[],
        },
        || panic!("auto not expected"),
        || times.next().unwrap(),
    )
    .unwrap();

    assert_eq!(acquired.access_token.as_ref(), "renewable-child");
    assert!(client.request.borrow().is_none());
}

#[test]
fn token_inside_handoff_margin_is_never_returned() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_root(&cache_dir, now, "root-token");
    cache_derived(&cache_dir, now + Duration::seconds(30), "unsafe-child");
    let root_key = root_cache_key("developer");
    let CacheEntry::Root(mut root) = load_cache_entry(&cache_dir, &root_key).unwrap().unwrap()
    else {
        panic!("expected root")
    };
    delete_cache_entry(&cache_dir, &root_key).unwrap();
    root.expires_at = TokenExpiry::new(now + Duration::seconds(30));
    save_cache_entry(&cache_dir, &root_key, &CacheEntry::Root(root)).unwrap();
    let client = no_response_client();
    let config: Config = CONFIG.parse().unwrap();
    let mut times = [now, now].into_iter();

    let result = super::acquire::acquire_with_clock(
        &client,
        &AcquireRequest {
            config: &config,
            cache_dir: &cache_dir,
            profile_name: "reader",
            repositories: &[],
        },
        || panic!("auto not expected"),
        || times.next().unwrap(),
    );

    assert!(matches!(result, Err(TokenError::NoSourceTokenCached(_))));
    assert!(client.request.borrow().is_none());
}

#[test]
fn cached_child_is_not_returned_when_root_provenance_is_missing() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_root(&cache_dir, now, "root-token");
    cache_derived(&cache_dir, now + Duration::hours(1), "cached-child");
    delete_cache_entry(&cache_dir, &root_cache_key("developer")).unwrap();
    let client = no_response_client();
    let config: Config = CONFIG.parse().unwrap();

    let result = super::acquire::acquire_with_clock(
        &client,
        &AcquireRequest {
            config: &config,
            cache_dir: &cache_dir,
            profile_name: "reader",
            repositories: &[],
        },
        || panic!("auto not expected"),
        || panic!("clock is not sampled before root provenance is established"),
    );

    assert!(matches!(result, Err(TokenError::NoSourceTokenCached(_))));
    assert!(client.request.borrow().is_none());
}

#[test]
fn failed_displaced_revocation_leaves_the_renewed_token_persisted() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_root(&cache_dir, now, "root-token");
    let cache_key = cache_derived(&cache_dir, now + Duration::minutes(5), "renewable-child");
    let mut failing_client = client(IssuedScopedToken {
        access_token: "persisted-child".into(),
        expires_at: Some(TokenExpiry::new(now + Duration::hours(1)).to_string()),
    });
    failing_client.revoke_fails = true;
    let config: Config = CONFIG.parse().unwrap();
    let mut times = [now, now, now].into_iter();

    let result = super::acquire::acquire_with_clock(
        &failing_client,
        &AcquireRequest {
            config: &config,
            cache_dir: &cache_dir,
            profile_name: "reader",
            repositories: &[],
        },
        || panic!("auto not expected"),
        || times.next().unwrap(),
    );

    assert!(matches!(
        result,
        Err(TokenError::RevocationFailed { context, .. })
            if matches!(&*context, TokenError::RenewalPersisted(profile) if profile == "reader")
    ));
    assert_eq!(&*failing_client.revoked.borrow(), &["renewable-child"]);
    let CacheEntry::Derived(cached) = load_cache_entry(&cache_dir, &cache_key).unwrap().unwrap()
    else {
        panic!("expected derived entry")
    };
    assert_eq!(cached.access_token.as_ref(), "persisted-child");
}
