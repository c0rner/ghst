use super::*;
use crate::cache::{
    CacheStore, Record, compute_cache_key, delete_cache_entry, load_cache_entry, write_test_entry,
};
use crate::config::Config;
use crate::credential::store::{
    CommitBaseOutcome, CommitScopedOutcome, DeleteBaseOutcome, IssuanceGuard, IssuanceGuardStore,
    ReadCredentials, ReplaceOutcome, SourceGuard, WriteCredentials,
};
use crate::credential::{
    AccessToken, BaseCredential, ScopedCredential, TokenExpiry, authority_fingerprint,
    policy_fingerprint,
};
use crate::profile::{AppAuthority, ResolvedTokenProfile};
use crate::token::base::persist_base_response;
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
    scoped: RefCell<Option<Result<IssuedScopedToken, RemoteError>>>,
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
    ) -> Result<(), RemoteError> {
        self.revoked.borrow_mut().push(access_token.to_owned());
        if self.revoke_fails {
            Err(RemoteError::Http {
                status: 500,
                message: "revocation failed".into(),
            })
        } else {
            Ok(())
        }
    }
}

impl BaseTokenClient for MockClient {
    fn get_user(&self, _access_token: &str) -> Result<GitHubUser, RemoteError> {
        Ok(GitHubUser {
            login: "octocat".into(),
        })
    }
}

impl ScopedTokenClient for MockClient {
    fn create_scoped_token(
        &self,
        request: &ScopedTokenRequest<'_>,
    ) -> Result<IssuedScopedToken, RemoteError> {
        self.request.replace(Some(serde_json::json!({
            "client_id": request.client_id,
            "client_secret": request.client_secret,
            "base_token": request.base_token,
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

fn cache_base(cache_dir: &Path, now: OffsetDateTime, token: &str) {
    let entry = Record::Base(BaseCredential {
        profile: "developer".into(),
        authority_fingerprint: authority_fingerprint("id", "acme"),
        github_user: "octocat".into(),
        expires_at: TokenExpiry::new(now + Duration::hours(2)),
        access_token: token.into(),
    });
    write_test_entry(cache_dir, &base_cache_key("developer"), &entry).unwrap();
}

fn cache_scoped(cache_dir: &Path, expiry: OffsetDateTime, token: &str) -> String {
    let base_key = base_cache_key("developer");
    let Record::Base(base) = load_cache_entry(cache_dir, &base_key).unwrap().unwrap() else {
        panic!("expected base")
    };
    let permissions = BTreeMap::from([
        ("contents".to_owned(), "read".to_owned()),
        ("pull_requests".to_owned(), "write".to_owned()),
    ]);
    let cache_key = compute_cache_key("reader", "acme/api");
    let entry = Record::Scoped(ScopedCredential {
        profile: "reader".into(),
        source_profile: "developer".into(),
        source_authority_fingerprint: authority_fingerprint("id", "acme"),
        parent_generation: base.generation_fingerprint(),
        policy_fingerprint: policy_fingerprint("acme", "acme/api", &permissions),
        github_user: "octocat".into(),
        repo_scope: "acme/api".into(),
        expires_at: TokenExpiry::new(expiry),
        access_token: token.into(),
    });
    write_test_entry(cache_dir, &cache_key, &entry).unwrap();
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
        scoped: RefCell::new(Some(Err(RemoteError::Http {
            status,
            message: "request rejected".into(),
        }))),
        request: RefCell::new(None),
        revoked: RefCell::new(Vec::new()),
        revoke_fails: false,
    }
}

fn base_request<'a>(profile: &'a ResolvedTokenProfile<'a>) -> AcquireRequest<'a> {
    match profile {
        ResolvedTokenProfile::Base { name, app } => AcquireRequest::Base {
            profile_name: name,
            authority: app.authority,
        },
        ResolvedTokenProfile::Scoped { .. } => panic!("expected base profile"),
    }
}

fn scoped_request<'a>(profile: &'a ResolvedTokenProfile<'a>) -> AcquireRequest<'a> {
    match profile {
        ResolvedTokenProfile::Scoped {
            name,
            source_name,
            app,
            repository_scope,
            permissions,
        } => AcquireRequest::Scoped {
            profile_name: name,
            source_name,
            app: *app,
            permissions,
            repositories: crate::repository::RepositorySelection::resolve(
                &[],
                repository_scope,
                app.authority.account,
                || panic!("auto not expected"),
            )
            .unwrap(),
        },
        ResolvedTokenProfile::Base { .. } => panic!("expected scoped profile"),
    }
}

#[test]
fn base_lifetime_requires_a_representable_value_beyond_the_margin() {
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000)
        .unwrap()
        .replace_nanosecond(500_000_000)
        .unwrap();
    for value in [None, Some(0), Some(30), Some(u64::MAX)] {
        assert!(matches!(
            validate_base_expiry::<crate::cache::CacheError>(value, now),
            Err(TokenError::InvalidLifetime { .. })
        ));
    }
    let lifetime = 24 * 60 * 60;
    let expiry = validate_base_expiry::<crate::cache::CacheError>(Some(lifetime), now)
        .unwrap()
        .value();
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
            validate_scoped_expiry::<crate::cache::CacheError>(value.as_deref(), now),
            Err(TokenError::InvalidLifetime { .. })
        ));
    }
    let expiry = TokenExpiry::new(now + Duration::hours(24));
    assert_eq!(
        validate_scoped_expiry::<crate::cache::CacheError>(Some(&expiry.to_string()), now).unwrap(),
        expiry
    );
}

#[test]
fn response_receipt_time_rejects_latency_crossing_the_handoff_margin() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_base(&cache_dir, now, "base-token");
    let client = client(IssuedScopedToken {
        access_token: "too-late".into(),
        expires_at: Some(TokenExpiry::new(now + Duration::seconds(40)).to_string()),
    });
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("reader").unwrap();
    let mut times = [now, now, now + Duration::seconds(15)].into_iter();

    let result = super::acquire::acquire_with_clock(
        &client,
        &CacheStore::new(&cache_dir),
        scoped_request(&profile),
        || times.next().unwrap(),
    );

    assert!(matches!(result, Err(TokenError::InvalidLifetime { .. })));
    assert_eq!(&*client.revoked.borrow(), &["too-late"]);
}

#[test]
fn base_acquisition_returns_cached_token() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_base(&cache_dir, now, "base-token");
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("developer").unwrap();
    let client = client(IssuedScopedToken {
        access_token: "unused".into(),
        expires_at: None,
    });
    let acquired = acquire(
        &client,
        &CacheStore::new(&cache_dir),
        base_request(&profile),
    )
    .unwrap();
    assert_eq!(acquired.access_token.as_ref(), "base-token");
    assert_eq!(acquired.repo_scope, "all");
}

#[test]
fn base_acquisition_rejects_a_token_at_the_handoff_boundary() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_base(&cache_dir, now, "unsafe-base");
    let key = base_cache_key("developer");
    let Record::Base(mut base) = load_cache_entry(&cache_dir, &key).unwrap().unwrap() else {
        panic!("expected base entry")
    };
    base.expires_at = TokenExpiry::new(now + Duration::seconds(30));
    write_test_entry(&cache_dir, &key, &Record::Base(base)).unwrap();
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("developer").unwrap();

    assert!(matches!(
        super::acquire::acquire_with_clock(
            &no_response_client(),
            &CacheStore::new(&cache_dir),
            base_request(&profile),
            || now,
        ),
        Err(TokenError::NoBaseTokenCached(profile)) if profile == "developer"
    ));
}

#[test]
fn invalid_base_response_is_revoked_and_not_persisted() {
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("developer").unwrap();
    let ResolvedTokenProfile::Base { app, .. } = profile else {
        panic!("expected base profile");
    };
    let client = client(IssuedScopedToken {
        access_token: "unused".into(),
        expires_at: None,
    });
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let response = IssuedBaseToken {
        access_token: "bad-base".into(),
        expires_in: None,
    };
    let store = CacheStore::new(&cache_dir);
    let guard = store.issuance_guard().unwrap();
    assert!(matches!(
        persist_base_response(
            &client,
            &app,
            "developer",
            &store,
            response,
            OffsetDateTime::now_utc(),
            guard,
        ),
        Err(TokenError::InvalidLifetime { .. })
    ));
    assert_eq!(&*client.revoked.borrow(), &["bad-base"]);
    assert!(
        load_cache_entry(&cache_dir, &base_cache_key("developer"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn scoped_acquisition_sends_exact_narrowing_request() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_base(&cache_dir, now, "base-token");
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
    let profile = config.resolve_token_profile("reader").unwrap();
    let acquired = acquire(
        &client,
        &CacheStore::new(&cache_dir),
        scoped_request(&profile),
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
            "base_token": "base-token",
            "target": "acme",
            "repositories": ["api", "web"],
            "permissions": {"contents": "read", "pull_requests": "write"},
        })
    );
    let Record::Scoped(cached) = load_cache_entry(
        &cache_dir,
        &compute_cache_key("reader", "acme/api,acme/web"),
    )
    .unwrap()
    .unwrap() else {
        panic!("expected scoped entry")
    };
    assert_eq!(cached.expires_at, exact_expiry);
}

#[test]
fn permanent_scoped_rejection_evicts_the_rejected_base() {
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("reader").unwrap();
    for status in [401, 404] {
        let now = OffsetDateTime::now_utc();
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_base(&cache_dir, now, "rejected-base");
        let result = acquire(
            &failing_scoped_client(status),
            &CacheStore::new(&cache_dir),
            scoped_request(&profile),
        );

        assert!(
            matches!(result, Err(TokenError::NoSourceBaseTokenCached(profile)) if profile == "developer")
        );
        assert!(
            load_cache_entry(&cache_dir, &base_cache_key("developer"))
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn scoped_policy_and_transient_rejections_retain_the_base() {
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("reader").unwrap();
    for status in [403, 500] {
        let now = OffsetDateTime::now_utc();
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_base(&cache_dir, now, "retained-base");
        let result = acquire(
            &failing_scoped_client(status),
            &CacheStore::new(&cache_dir),
            scoped_request(&profile),
        );

        match status {
            403 => assert!(matches!(
                result,
                Err(TokenError::ScopedTokenForbidden { .. })
            )),
            500 => assert!(matches!(
                result,
                Err(TokenError::GitHub(RemoteError::Http { status: 500, .. }))
            )),
            _ => unreachable!("test status is fixed"),
        }
        assert_eq!(
            load_cache_entry(&cache_dir, &base_cache_key("developer"))
                .unwrap()
                .unwrap()
                .access_token()
                .as_ref(),
            "retained-base"
        );
    }
}

#[test]
fn invalid_scoped_response_is_revoked_without_cache_entry() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_base(&cache_dir, now, "base-token");
    let client = client(IssuedScopedToken {
        access_token: "bad-child".into(),
        expires_at: None,
    });
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("reader").unwrap();
    assert!(matches!(
        acquire(
            &client,
            &CacheStore::new(&cache_dir),
            scoped_request(&profile)
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
    ) -> Result<(), RemoteError> {
        Ok(())
    }
}

impl ScopedTokenClient for RejectingGenerationChangingClient<'_> {
    fn create_scoped_token(
        &self,
        _request: &ScopedTokenRequest<'_>,
    ) -> Result<IssuedScopedToken, RemoteError> {
        let key = base_cache_key("developer");
        delete_cache_entry(self.cache_dir, &key).unwrap();
        cache_base(self.cache_dir, self.now, "replacement-base");
        Err(RemoteError::Http {
            status: 401,
            message: "rejected old base".into(),
        })
    }
}

#[test]
fn permanent_rejection_preserves_a_concurrent_base_replacement() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_base(&cache_dir, now, "rejected-base");
    let client = RejectingGenerationChangingClient {
        cache_dir: &cache_dir,
        now,
    };
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("reader").unwrap();

    let result = acquire(
        &client,
        &CacheStore::new(&cache_dir),
        scoped_request(&profile),
    );

    assert!(
        matches!(result, Err(TokenError::BaseGenerationChanged(profile)) if profile == "developer")
    );
    assert_eq!(
        load_cache_entry(&cache_dir, &base_cache_key("developer"))
            .unwrap()
            .unwrap()
            .access_token()
            .as_ref(),
        "replacement-base"
    );
}

impl RevokeTokenClient for GenerationChangingClient<'_> {
    fn delete_token(
        &self,
        _client_id: &str,
        _client_secret: &str,
        access_token: &str,
    ) -> Result<(), RemoteError> {
        self.revoked.borrow_mut().push(access_token.to_owned());
        Ok(())
    }
}

impl ScopedTokenClient for GenerationChangingClient<'_> {
    fn create_scoped_token(
        &self,
        _request: &ScopedTokenRequest<'_>,
    ) -> Result<IssuedScopedToken, RemoteError> {
        let key = base_cache_key("developer");
        delete_cache_entry(self.cache_dir, &key).unwrap();
        cache_base(self.cache_dir, self.now, "replacement-base");
        Ok(IssuedScopedToken {
            access_token: "orphaned-child".into(),
            expires_at: Some(
                TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(1)).to_string(),
            ),
        })
    }
}

#[test]
fn base_generation_change_revokes_candidate_and_requests_retry() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_base(&cache_dir, now, "base-token");
    let client = GenerationChangingClient {
        cache_dir: &cache_dir,
        now,
        revoked: RefCell::new(Vec::new()),
    };
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("reader").unwrap();
    assert!(matches!(
        acquire(
            &client,
            &CacheStore::new(&cache_dir),
            scoped_request(&profile),
        ),
        Err(TokenError::BaseGenerationChanged(profile)) if profile == "developer"
    ));
    assert_eq!(&*client.revoked.borrow(), &["orphaned-child"]);
}

#[test]
fn cached_scoped_token_remains_usable_after_base_expiry() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_base(&cache_dir, now, "base-token");
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("reader").unwrap();
    let first_client = client(IssuedScopedToken {
        access_token: "child-token".into(),
        expires_at: Some(
            TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(6)).to_string(),
        ),
    });
    acquire(
        &first_client,
        &CacheStore::new(&cache_dir),
        scoped_request(&profile),
    )
    .unwrap();

    let base_key = base_cache_key("developer");
    let Record::Base(mut base) = load_cache_entry(&cache_dir, &base_key).unwrap().unwrap() else {
        panic!("expected base");
    };
    delete_cache_entry(&cache_dir, &base_key).unwrap();
    base.expires_at = TokenExpiry::new(now - Duration::minutes(1));
    write_test_entry(&cache_dir, &base_key, &Record::Base(base)).unwrap();

    let unused_client = MockClient {
        scoped: RefCell::new(None),
        request: RefCell::new(None),
        revoked: RefCell::new(Vec::new()),
        revoke_fails: false,
    };
    let acquired = acquire(
        &unused_client,
        &CacheStore::new(&cache_dir),
        scoped_request(&profile),
    )
    .unwrap();
    assert_eq!(acquired.access_token.as_ref(), "child-token");
    assert!(unused_client.request.borrow().is_none());
}

#[test]
fn renewable_scoped_token_is_replaced_and_displaced_token_is_revoked() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_base(&cache_dir, now, "base-token");
    let cache_key = cache_scoped(&cache_dir, now + Duration::minutes(5), "renewable-child");
    let exact_expiry = TokenExpiry::new(now + Duration::hours(1));
    let client = client(IssuedScopedToken {
        access_token: "renewed-child".into(),
        expires_at: Some(exact_expiry.to_string()),
    });
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("reader").unwrap();
    let mut times = [now, now, now].into_iter();

    let acquired = super::acquire::acquire_with_clock(
        &client,
        &CacheStore::new(&cache_dir),
        scoped_request(&profile),
        || times.next().unwrap(),
    )
    .unwrap();

    assert_eq!(acquired.access_token.as_ref(), "renewed-child");
    assert_eq!(&*client.revoked.borrow(), &["renewable-child"]);
    let Record::Scoped(cached) = load_cache_entry(&cache_dir, &cache_key).unwrap().unwrap() else {
        panic!("expected scoped entry")
    };
    assert_eq!(cached.access_token.as_ref(), "renewed-child");
    assert_eq!(cached.expires_at, exact_expiry);
}

#[test]
fn renewable_scoped_token_falls_back_when_base_is_not_usable() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_base(&cache_dir, now, "base-token");
    cache_scoped(&cache_dir, now + Duration::minutes(5), "renewable-child");
    let base_key = base_cache_key("developer");
    let Record::Base(mut base) = load_cache_entry(&cache_dir, &base_key).unwrap().unwrap() else {
        panic!("expected base")
    };
    delete_cache_entry(&cache_dir, &base_key).unwrap();
    base.expires_at = TokenExpiry::new(now + Duration::seconds(30));
    write_test_entry(&cache_dir, &base_key, &Record::Base(base)).unwrap();
    let client = no_response_client();
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("reader").unwrap();
    let mut times = [now, now].into_iter();

    let acquired = super::acquire::acquire_with_clock(
        &client,
        &CacheStore::new(&cache_dir),
        scoped_request(&profile),
        || times.next().unwrap(),
    )
    .unwrap();

    assert_eq!(acquired.access_token.as_ref(), "renewable-child");
    assert!(client.request.borrow().is_none());
}

#[test]
fn fallback_child_inside_handoff_margin_is_rejected_when_base_cannot_mint() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_base(&cache_dir, now, "base-token");
    cache_scoped(&cache_dir, now + Duration::seconds(31), "renewable-child");
    let base_key = base_cache_key("developer");
    let Record::Base(mut base) = load_cache_entry(&cache_dir, &base_key).unwrap().unwrap() else {
        panic!("expected base")
    };
    delete_cache_entry(&cache_dir, &base_key).unwrap();
    base.expires_at = TokenExpiry::new(now + Duration::seconds(30));
    write_test_entry(&cache_dir, &base_key, &Record::Base(base)).unwrap();
    let client = no_response_client();
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("reader").unwrap();
    let mut times = [now, now + Duration::seconds(2)].into_iter();

    let result = super::acquire::acquire_with_clock(
        &client,
        &CacheStore::new(&cache_dir),
        scoped_request(&profile),
        || times.next().unwrap(),
    );

    assert!(matches!(
        result,
        Err(TokenError::NoSourceBaseTokenCached(_))
    ));
    assert!(client.request.borrow().is_none());
}

#[test]
fn fallback_child_on_valid_side_of_handoff_margin_is_returned_when_base_cannot_mint() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_base(&cache_dir, now, "base-token");
    cache_scoped(&cache_dir, now + Duration::seconds(33), "renewable-child");
    let base_key = base_cache_key("developer");
    let Record::Base(mut base) = load_cache_entry(&cache_dir, &base_key).unwrap().unwrap() else {
        panic!("expected base")
    };
    delete_cache_entry(&cache_dir, &base_key).unwrap();
    base.expires_at = TokenExpiry::new(now + Duration::seconds(30));
    write_test_entry(&cache_dir, &base_key, &Record::Base(base)).unwrap();
    let client = no_response_client();
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("reader").unwrap();
    let mut times = [now, now + Duration::seconds(2)].into_iter();

    let acquired = super::acquire::acquire_with_clock(
        &client,
        &CacheStore::new(&cache_dir),
        scoped_request(&profile),
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
    cache_base(&cache_dir, now, "base-token");
    cache_scoped(&cache_dir, now + Duration::seconds(30), "unsafe-child");
    let base_key = base_cache_key("developer");
    let Record::Base(mut base) = load_cache_entry(&cache_dir, &base_key).unwrap().unwrap() else {
        panic!("expected base")
    };
    delete_cache_entry(&cache_dir, &base_key).unwrap();
    base.expires_at = TokenExpiry::new(now + Duration::seconds(30));
    write_test_entry(&cache_dir, &base_key, &Record::Base(base)).unwrap();
    let client = no_response_client();
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("reader").unwrap();
    let mut times = [now, now].into_iter();

    let result = super::acquire::acquire_with_clock(
        &client,
        &CacheStore::new(&cache_dir),
        scoped_request(&profile),
        || times.next().unwrap(),
    );

    assert!(matches!(
        result,
        Err(TokenError::NoSourceBaseTokenCached(_))
    ));
    assert!(client.request.borrow().is_none());
}

#[test]
fn cached_child_is_not_returned_when_base_provenance_is_missing() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_base(&cache_dir, now, "base-token");
    cache_scoped(&cache_dir, now + Duration::hours(1), "cached-child");
    delete_cache_entry(&cache_dir, &base_cache_key("developer")).unwrap();
    let client = no_response_client();
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("reader").unwrap();

    let result = super::acquire::acquire_with_clock(
        &client,
        &CacheStore::new(&cache_dir),
        scoped_request(&profile),
        || panic!("clock is not sampled before base provenance is established"),
    );

    assert!(matches!(
        result,
        Err(TokenError::NoSourceBaseTokenCached(_))
    ));
    assert!(client.request.borrow().is_none());
}

#[test]
fn failed_displaced_revocation_leaves_the_renewed_token_persisted() {
    let now = OffsetDateTime::now_utc();
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    cache_base(&cache_dir, now, "base-token");
    let cache_key = cache_scoped(&cache_dir, now + Duration::minutes(5), "renewable-child");
    let mut failing_client = client(IssuedScopedToken {
        access_token: "persisted-child".into(),
        expires_at: Some(TokenExpiry::new(now + Duration::hours(1)).to_string()),
    });
    failing_client.revoke_fails = true;
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("reader").unwrap();
    let mut times = [now, now, now].into_iter();

    let result = super::acquire::acquire_with_clock(
        &failing_client,
        &CacheStore::new(&cache_dir),
        scoped_request(&profile),
        || times.next().unwrap(),
    );

    assert!(matches!(
        result,
        Err(TokenError::RevocationFailed { context, .. })
            if matches!(&*context, TokenError::RenewalPersisted(profile) if profile == "reader")
    ));
    assert_eq!(&*failing_client.revoked.borrow(), &["renewable-child"]);
    let Record::Scoped(cached) = load_cache_entry(&cache_dir, &cache_key).unwrap().unwrap() else {
        panic!("expected scoped entry")
    };
    assert_eq!(cached.access_token.as_ref(), "persisted-child");
}

#[derive(Debug, PartialEq, Eq)]
struct MockStoreError;

impl std::fmt::Display for MockStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "simulated store failure")
    }
}

impl std::error::Error for MockStoreError {}

fn fake_base(now: OffsetDateTime) -> BaseCredential {
    BaseCredential {
        profile: "developer".into(),
        authority_fingerprint: authority_fingerprint("id", "acme"),
        github_user: "octocat".into(),
        expires_at: TokenExpiry::new(now + Duration::hours(2)),
        access_token: AccessToken::from("base-token"),
    }
}

fn fake_scoped(now: OffsetDateTime, token: &str, expiry: OffsetDateTime) -> ScopedCredential {
    let permissions = BTreeMap::from([
        ("contents".to_owned(), "read".to_owned()),
        ("pull_requests".to_owned(), "write".to_owned()),
    ]);
    ScopedCredential {
        profile: "reader".into(),
        source_profile: "developer".into(),
        source_authority_fingerprint: authority_fingerprint("id", "acme"),
        parent_generation: fake_base(now).generation_fingerprint(),
        policy_fingerprint: policy_fingerprint("acme", "acme/api", &permissions),
        github_user: "octocat".into(),
        repo_scope: "acme/api".into(),
        expires_at: TokenExpiry::new(expiry),
        access_token: AccessToken::from(token),
    }
}

struct FakeCredentialsStore {
    now: OffsetDateTime,
    renewable: bool,
    scoped: RefCell<Option<ScopedCredential>>,
    commit_scoped_result: RefCell<Option<Result<CommitScopedOutcome, MockStoreError>>>,
    renew_scoped_result: RefCell<Option<Result<ReplaceOutcome<ScopedCredential>, MockStoreError>>>,
}

impl FakeCredentialsStore {
    fn new(now: OffsetDateTime) -> Self {
        Self {
            now,
            renewable: false,
            scoped: RefCell::new(None),
            commit_scoped_result: RefCell::new(None),
            renew_scoped_result: RefCell::new(None),
        }
    }
}

impl ReadCredentials for FakeCredentialsStore {
    type Error = MockStoreError;

    fn read_base(&self, profile: &str) -> Result<Option<BaseCredential>, Self::Error> {
        Ok(
            (self.now > OffsetDateTime::UNIX_EPOCH && profile == "developer")
                .then(|| fake_base(self.now)),
        )
    }

    fn read_scoped(
        &self,
        profile: &str,
        repo_scope: &str,
    ) -> Result<Option<ScopedCredential>, Self::Error> {
        Ok(self.scoped.borrow_mut().take().or_else(|| {
            (self.renewable && profile == "reader" && repo_scope == "acme/api")
                .then(|| fake_scoped(self.now, "renewable-token", self.now + Duration::minutes(5)))
        }))
    }
}

impl IssuanceGuardStore for FakeCredentialsStore {
    type Error = MockStoreError;

    fn issuance_guard(&self) -> Result<IssuanceGuard, Self::Error> {
        Ok(IssuanceGuard::new(1))
    }
}

impl WriteCredentials for FakeCredentialsStore {
    type Error = MockStoreError;

    fn commit_base(
        &self,
        _candidate: &BaseCredential,
        _guard: IssuanceGuard,
    ) -> Result<CommitBaseOutcome, Self::Error> {
        Ok(CommitBaseOutcome::Saved)
    }

    fn commit_scoped(
        &self,
        _entry: &ScopedCredential,
        _guard: IssuanceGuard,
        _source: &SourceGuard<'_>,
    ) -> Result<CommitScopedOutcome, Self::Error> {
        self.commit_scoped_result
            .borrow_mut()
            .take()
            .unwrap_or(Ok(CommitScopedOutcome::Saved))
    }

    fn renew_scoped(
        &self,
        _expected: &ScopedCredential,
        _entry: &ScopedCredential,
        _guard: IssuanceGuard,
        _source: &SourceGuard<'_>,
        _observed_at: OffsetDateTime,
    ) -> Result<ReplaceOutcome<ScopedCredential>, Self::Error> {
        self.renew_scoped_result.borrow_mut().take().unwrap()
    }

    fn delete_base_if_generation(
        &self,
        _profile: &str,
        _expected_generation: &str,
    ) -> Result<DeleteBaseOutcome, Self::Error> {
        Ok(DeleteBaseOutcome::Deleted)
    }
}

fn candidate_client(token: &str, now: OffsetDateTime) -> MockClient {
    client(IssuedScopedToken {
        access_token: token.into(),
        expires_at: Some(TokenExpiry::new(now + Duration::hours(1)).to_string()),
    })
}

enum FakeAcquireInjection {
    Commit(Result<CommitScopedOutcome, MockStoreError>),
    Renew(Result<ReplaceOutcome<ScopedCredential>, MockStoreError>),
}

enum FakeAcquireExpected {
    StorageError,
    EpochChanged,
    BaseGenChanged,
    Winner(&'static str),
}

#[test]
fn fake_storage_workflow_injection_and_candidate_cleanup() {
    let now = OffsetDateTime::now_utc();
    let cases =
        [
            (
                "cand-commit-err",
                FakeAcquireInjection::Commit(Err(MockStoreError)),
                FakeAcquireExpected::StorageError,
            ),
            (
                "cand-commit-epoch",
                FakeAcquireInjection::Commit(Ok(CommitScopedOutcome::EpochChanged)),
                FakeAcquireExpected::EpochChanged,
            ),
            (
                "cand-commit-gen",
                FakeAcquireInjection::Commit(Ok(CommitScopedOutcome::BaseGenerationChanged)),
                FakeAcquireExpected::BaseGenChanged,
            ),
            (
                "cand-commit-winner",
                FakeAcquireInjection::Commit(Ok(CommitScopedOutcome::Retained(Box::new(
                    fake_scoped(now, "winner-token", now + Duration::hours(1)),
                )))),
                FakeAcquireExpected::Winner("winner-token"),
            ),
            (
                "cand-renew-err",
                FakeAcquireInjection::Renew(Err(MockStoreError)),
                FakeAcquireExpected::StorageError,
            ),
            (
                "cand-renew-epoch",
                FakeAcquireInjection::Renew(Ok(ReplaceOutcome::EpochChanged)),
                FakeAcquireExpected::EpochChanged,
            ),
            (
                "cand-renew-gen",
                FakeAcquireInjection::Renew(Ok(ReplaceOutcome::BaseGenerationChanged)),
                FakeAcquireExpected::BaseGenChanged,
            ),
            (
                "cand-renew-winner",
                FakeAcquireInjection::Renew(Ok(ReplaceOutcome::Retained(fake_scoped(
                    now,
                    "winner-token",
                    now + Duration::hours(1),
                )))),
                FakeAcquireExpected::Winner("winner-token"),
            ),
        ];

    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("reader").unwrap();

    for (cand_token, injection, expected) in cases {
        let mut store = FakeCredentialsStore::new(now);
        let client = candidate_client(cand_token, now);
        match injection {
            FakeAcquireInjection::Commit(res) => {
                *store.commit_scoped_result.borrow_mut() = Some(res);
            }
            FakeAcquireInjection::Renew(res) => {
                store.renewable = true;
                *store.renew_scoped_result.borrow_mut() = Some(res);
            }
        }
        let result =
            super::acquire::acquire_with_clock(&client, &store, scoped_request(&profile), || now);
        assert_eq!(
            &*client.revoked.borrow(),
            &[cand_token],
            "candidate must be revoked on error/conflict/retention"
        );

        match expected {
            FakeAcquireExpected::StorageError => {
                assert!(matches!(result, Err(TokenError::Storage(MockStoreError))));
            }
            FakeAcquireExpected::EpochChanged => {
                assert!(matches!(result, Err(TokenError::EpochChanged(ref p)) if p == "reader"));
            }
            FakeAcquireExpected::BaseGenChanged => {
                assert!(
                    matches!(result, Err(TokenError::BaseGenerationChanged(ref s)) if s == "developer")
                );
            }
            FakeAcquireExpected::Winner(token) => {
                assert_eq!(result.unwrap().access_token.as_ref(), token);
            }
        }
    }
}

struct FakeBaseReadStore {
    entry: Option<BaseCredential>,
}

impl ReadCredentials for FakeBaseReadStore {
    type Error = MockStoreError;

    fn read_base(&self, _profile: &str) -> Result<Option<BaseCredential>, Self::Error> {
        Ok(self.entry.as_ref().map(|entry| BaseCredential {
            profile: entry.profile.clone(),
            authority_fingerprint: entry.authority_fingerprint.clone(),
            github_user: entry.github_user.clone(),
            expires_at: entry.expires_at,
            access_token: AccessToken::from(entry.access_token.as_ref()),
        }))
    }

    fn read_scoped(
        &self,
        _profile: &str,
        _repo_scope: &str,
    ) -> Result<Option<ScopedCredential>, Self::Error> {
        Ok(None)
    }
}

#[test]
fn base_lookup_maps_provenance_mismatches() {
    let now = OffsetDateTime::now_utc();
    let authority = AppAuthority {
        account: "acme",
        client_id: "id",
    };
    let mut entry = fake_base(now);
    entry.profile = "wrong-profile".into();
    let inconsistent = FakeBaseReadStore { entry: Some(entry) };

    assert!(matches!(
        load_current_base_entry(&inconsistent, "developer", &authority),
        Err(TokenError::InconsistentCacheMetadata { profile, found })
            if profile == "developer" && found == "wrong-profile"
    ));

    let mismatched_authority = AppAuthority {
        account: "other-account",
        client_id: "id",
    };
    let stale = FakeBaseReadStore {
        entry: Some(fake_base(now)),
    };
    assert!(
        load_current_base_entry(&stale, "developer", &mismatched_authority)
            .unwrap()
            .is_none()
    );
}

#[test]
fn scoped_acquisition_maps_profile_mismatch_to_an_error() {
    let now = OffsetDateTime::now_utc();
    let store = FakeCredentialsStore::new(now);
    let mut entry = fake_scoped(now, "cached-token", now + Duration::hours(1));
    entry.profile = "wrong-profile".into();
    store.scoped.replace(Some(entry));

    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("reader").unwrap();
    let client = no_response_client();

    assert!(matches!(
        super::acquire::acquire_with_clock(&client, &store, scoped_request(&profile), || now),
        Err(TokenError::InconsistentCacheMetadata { profile, found })
            if profile == "reader" && found == "wrong-profile"
    ));
    assert!(client.request.borrow().is_none());
}

#[test]
fn scoped_acquisition_treats_other_provenance_mismatches_as_a_cache_miss() {
    let now = OffsetDateTime::now_utc();
    let store = FakeCredentialsStore::new(now);
    let mut entry = fake_scoped(now, "cached-token", now + Duration::hours(1));
    entry.source_profile = "wrong-source".into();
    store.scoped.replace(Some(entry));

    let minted_expiry = TokenExpiry::new(now + Duration::hours(2));
    let client = client(IssuedScopedToken {
        access_token: "minted-token".into(),
        expires_at: Some(minted_expiry.to_string()),
    });
    let config: Config = CONFIG.parse().unwrap();
    let profile = config.resolve_token_profile("reader").unwrap();

    let acquired =
        super::acquire::acquire_with_clock(&client, &store, scoped_request(&profile), || now)
            .unwrap();

    assert_eq!(acquired.access_token.as_ref(), "minted-token");
    assert!(client.request.borrow().is_some());
    assert!(client.revoked.borrow().is_empty());
}
