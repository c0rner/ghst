use super::validation::MAX_ROOT_LIFETIME_SECONDS;
use super::*;
use crate::cache::{
    CACHE_SCHEMA_VERSION, CacheEntry, RootCacheEntry, TokenExpiry, authority_fingerprint,
    cache_epoch, compute_cache_key, delete_cache_entry, format_rfc3339, load_cache_entry,
    save_cache_entry,
};
use crate::config::{Config, GitHubAppConfig, ProfileConfig};
use crate::github::{
    AccessTokenResponse, GitHubError, RevokeTokenClient, RootTokenClient, ScopedTokenClient,
    ScopedTokenResponse, UserResponse,
};
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
    scoped: RefCell<Option<Result<ScopedTokenResponse, GitHubError>>>,
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
    fn get_user(&self, _access_token: &str) -> Result<UserResponse, GitHubError> {
        Ok(UserResponse {
            login: "octocat".into(),
            id: 1,
            name: None,
            email: None,
        })
    }
}

impl ScopedTokenClient for MockClient {
    fn create_scoped_token(
        &self,
        client_id: &str,
        client_secret: &str,
        root_token: &str,
        target: &str,
        repositories: Option<&[String]>,
        permissions: &BTreeMap<String, String>,
    ) -> Result<ScopedTokenResponse, GitHubError> {
        self.request.replace(Some(serde_json::json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "root_token": root_token,
            "target": target,
            "repositories": repositories,
            "permissions": permissions,
        })));
        self.scoped.borrow_mut().take().unwrap()
    }
}

fn client(response: ScopedTokenResponse) -> MockClient {
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
        issued_at: format_rfc3339(now),
        expires_at: TokenExpiry::new(now + Duration::hours(2)),
        access_token: token.into(),
    });
    save_cache_entry(cache_dir, &root_cache_key("developer"), &entry).unwrap();
}

#[test]
fn root_lifetime_requires_positive_bounded_value_and_margin() {
    let now = OffsetDateTime::now_utc();
    for value in [None, Some(0), Some(30), Some(MAX_ROOT_LIFETIME_SECONDS + 1)] {
        assert!(matches!(
            validate_root_expiry(value, now),
            Err(TokenError::InvalidLifetime { .. })
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
fn scoped_lifetime_enforces_margin_maximum_and_rounding_tolerance() {
    let now = OffsetDateTime::now_utc();
    for value in [
        Some("not-a-timestamp".to_owned()),
        Some(TokenExpiry::new(now + Duration::seconds(30)).to_string()),
        Some(TokenExpiry::new(now + Duration::hours(8) + Duration::seconds(2)).to_string()),
    ] {
        assert!(matches!(
            validate_scoped_expiry(value.as_deref(), now),
            Err(TokenError::InvalidLifetime { .. })
        ));
    }
    let issued = OffsetDateTime::parse(
        "2026-08-01T17:20:25.889841154Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert!(validate_scoped_expiry(Some("2026-08-02T01:20:26.000Z"), issued).is_ok());
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
    let client = client(ScopedTokenResponse {
        token: "unused".into(),
        expires_at: None,
        permissions: None,
        repositories: None,
    });
    let acquired = acquire(
        &client,
        &AcquireRequest {
            config: &config,
            cache_dir: &cache_dir,
            profile_name: "developer",
            repositories: &[],
            now,
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
                now,
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
    let client = client(ScopedTokenResponse {
        token: "unused".into(),
        expires_at: None,
        permissions: None,
        repositories: None,
    });
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let response = AccessTokenResponse {
        access_token: "bad-root".into(),
        token_type: "bearer".into(),
        expires_in: None,
        refresh_token: Some(zeroize::Zeroizing::new("refresh".into())),
        refresh_token_expires_in: Some(3600),
        scope: None,
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
    let expiry = TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(6)).to_string();
    let client = client(ScopedTokenResponse {
        token: "child-token".into(),
        expires_at: Some(expiry),
        permissions: None,
        repositories: None,
    });
    let config: Config = CONFIG.parse().unwrap();
    let acquired = acquire(
        &client,
        &AcquireRequest {
            config: &config,
            cache_dir: &cache_dir,
            profile_name: "reader",
            repositories: &[],
            now,
        },
        || panic!("auto not expected"),
    )
    .unwrap();
    assert_eq!(acquired.access_token.as_ref(), "child-token");
    assert_eq!(acquired.repo_scope, "acme/api");
    assert_eq!(
        client.request.borrow().as_ref().unwrap(),
        &serde_json::json!({
            "client_id": "id",
            "client_secret": "secret",
            "root_token": "root-token",
            "target": "acme",
            "repositories": ["api"],
            "permissions": {"contents": "read", "pull_requests": "write"},
        })
    );
}

#[test]
fn invalid_scoped_response_is_revoked_without_cache_entry() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_root(&cache_dir, now, "root-token");
    let client = client(ScopedTokenResponse {
        token: "bad-child".into(),
        expires_at: None,
        permissions: None,
        repositories: None,
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
                now,
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
        _client_id: &str,
        _client_secret: &str,
        _root_token: &str,
        _target: &str,
        _repositories: Option<&[String]>,
        _permissions: &BTreeMap<String, String>,
    ) -> Result<ScopedTokenResponse, GitHubError> {
        let key = root_cache_key("developer");
        delete_cache_entry(self.cache_dir, &key).unwrap();
        cache_root(self.cache_dir, self.now, "replacement-root");
        Ok(ScopedTokenResponse {
            token: "orphaned-child".into(),
            expires_at: Some(
                TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(1)).to_string(),
            ),
            permissions: None,
            repositories: None,
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
                now,
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
    let first_client = client(ScopedTokenResponse {
        token: "child-token".into(),
        expires_at: Some(
            TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(6)).to_string(),
        ),
        permissions: None,
        repositories: None,
    });
    let request = AcquireRequest {
        config: &config,
        cache_dir: &cache_dir,
        profile_name: "reader",
        repositories: &[],
        now,
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
