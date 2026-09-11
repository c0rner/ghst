use std::collections::BTreeMap;
use std::fmt;
use time::OffsetDateTime;

use super::{
    IssuedScopedToken, ScopedTokenClient, ScopedTokenRequest, TokenError, load_current_base_entry,
    revoke_with_context, validate_scoped_expiry,
};
use crate::credential::store::{
    DeleteBaseOutcome, IssuanceGuard, IssuanceGuardStore, ReadCredentials, WriteCredentials,
};
use crate::credential::{AccessToken, BaseCredential, TokenExpiry, authority_fingerprint};
use crate::domain::profile::{AppCredentials, PermissionLevel};
use crate::repository::RepositorySelection;

pub struct FreshScopedTokenRequest<'a> {
    pub profile_name: &'a str,
    pub source_name: &'a str,
    pub app: AppCredentials<'a>,
    pub repository_selection: &'a RepositorySelection,
    pub permissions: &'a BTreeMap<String, PermissionLevel>,
}

impl fmt::Debug for FreshScopedTokenRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FreshScopedTokenRequest")
            .field("profile_name", &self.profile_name)
            .field("source_name", &self.source_name)
            .field("app", &self.app)
            .field("repository_selection", &self.repository_selection)
            .field("permissions", &self.permissions)
            .finish()
    }
}

pub struct FreshScopedToken {
    pub access_token: AccessToken,
    pub expires_at: TokenExpiry,
    pub github_user: String,
    pub repo_scope: String,
    pub profile: String,
    pub source_profile: String,
    pub source_authority_fingerprint: String,
    pub issuance_guard: IssuanceGuard,
    pub expected_base_generation: String,
}

impl fmt::Debug for FreshScopedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FreshScopedToken")
            .field("access_token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("github_user", &self.github_user)
            .field("repo_scope", &self.repo_scope)
            .field("profile", &self.profile)
            .field("source_profile", &self.source_profile)
            .field(
                "source_authority_fingerprint",
                &self.source_authority_fingerprint,
            )
            .field("issuance_guard", &self.issuance_guard)
            .field("expected_base_generation", &self.expected_base_generation)
            .finish()
    }
}

pub fn issue_fresh_scoped<C, S, E, N>(
    client: &C,
    store: &S,
    request: &FreshScopedTokenRequest<'_>,
    mut now: N,
) -> Result<FreshScopedToken, TokenError<E>>
where
    C: ScopedTokenClient,
    S: ReadCredentials<Error = E> + WriteCredentials<Error = E> + IssuanceGuardStore<Error = E>,
    E: std::error::Error + 'static,
    N: FnMut() -> OffsetDateTime,
{
    let prepared = prepare(
        store,
        request.profile_name,
        request.source_name,
        request.app,
        request.permissions,
        request.repository_selection,
    )?;
    tracing::debug!(
        profile = prepared.profile_name,
        source_profile = prepared.source_name,
        repo_scope = prepared.scope,
        "prepared fresh scoped token request"
    );
    let guard = store.issuance_guard().map_err(TokenError::Storage)?;
    let expected_generation = prepared.base.generation_fingerprint();
    let request_time = now();
    let issued = issue(client, store, &prepared, request_time, &mut now)?;
    tracing::debug!(
        profile = prepared.profile_name,
        expires_at = %issued.expires_at,
        "received valid fresh scoped token from GitHub"
    );
    Ok(FreshScopedToken {
        access_token: issued.access_token,
        expires_at: issued.expires_at,
        github_user: prepared.base.github_user,
        repo_scope: prepared.scope,
        profile: prepared.profile_name.to_owned(),
        source_profile: prepared.source_name.to_owned(),
        source_authority_fingerprint: authority_fingerprint(
            prepared.app.authority.client_id,
            prepared.app.authority.account,
        ),
        issuance_guard: guard,
        expected_base_generation: expected_generation,
    })
}

pub(super) struct PreparedScopedToken<'a> {
    pub profile_name: &'a str,
    pub source_name: &'a str,
    pub app: AppCredentials<'a>,
    pub permissions: &'a BTreeMap<String, PermissionLevel>,
    pub base: BaseCredential,
    pub scope: String,
    pub repositories: Option<Vec<String>>,
}

pub(super) struct ValidatedScopedToken {
    pub access_token: AccessToken,
    pub expires_at: TokenExpiry,
    pub received_at: OffsetDateTime,
}

pub(super) fn prepare<'a, S, E>(
    store: &S,
    profile_name: &'a str,
    source_name: &'a str,
    app: AppCredentials<'a>,
    permissions: &'a BTreeMap<String, PermissionLevel>,
    repositories: &RepositorySelection,
) -> Result<PreparedScopedToken<'a>, TokenError<E>>
where
    S: ReadCredentials<Error = E>,
    E: std::error::Error + 'static,
{
    let scope = repositories.canonical();
    let repository_names = repositories.repository_names();
    tracing::debug!(
        profile = profile_name,
        source_profile = source_name,
        account = app.authority.account,
        repo_scope = scope,
        repositories = ?repository_names,
        permissions = ?permissions,
        "resolved scoped token policy"
    );
    let base = load_current_base_entry(store, source_name, &app.authority)?
        .ok_or_else(|| TokenError::NoSourceBaseTokenCached(source_name.to_owned()))?;
    Ok(PreparedScopedToken {
        profile_name,
        source_name,
        app,
        permissions,
        base,
        scope,
        repositories: repository_names,
    })
}

pub(super) fn issue<C, S, E, N>(
    client: &C,
    store: &S,
    prepared: &PreparedScopedToken<'_>,
    request_time: OffsetDateTime,
    now: &mut N,
) -> Result<ValidatedScopedToken, TokenError<E>>
where
    C: ScopedTokenClient,
    S: WriteCredentials<Error = E>,
    E: std::error::Error + 'static,
    N: FnMut() -> OffsetDateTime,
{
    if !prepared.base.expires_at.is_safe_to_handoff_at(request_time) {
        tracing::debug!(
            source_profile = prepared.source_name,
            expires_at = %prepared.base.expires_at,
            "base token is inside the handoff safety margin and cannot mint a scoped token"
        );
        return Err(TokenError::NoSourceBaseTokenCached(
            prepared.source_name.to_owned(),
        ));
    }
    tracing::debug!(
        source_profile = prepared.source_name,
        account = prepared.app.authority.account,
        repo_scope = prepared.scope,
        permissions = ?prepared.permissions,
        "requesting scoped token from GitHub"
    );
    let response = client.create_scoped_token(&ScopedTokenRequest {
        client_id: prepared.app.authority.client_id,
        client_secret: prepared.app.client_secret,
        base_token: prepared.base.access_token.as_ref(),
        target: prepared.app.authority.account,
        repositories: prepared.repositories.as_deref(),
        permissions: prepared.permissions,
    });
    let response = match response {
        Ok(response) => response,
        Err(crate::token::RemoteError::Http {
            status: 401 | 404, ..
        }) => return Err(permanent_rejection_error(store, prepared)),
        Err(source @ crate::token::RemoteError::Http { status: 403, .. }) => {
            tracing::debug!(
                source_profile = prepared.source_name,
                account = prepared.app.authority.account,
                repo_scope = prepared.scope,
                permissions = ?prepared.permissions,
                "GitHub rejected the scoped token request; requested permissions or repository access likely exceed the GitHub App installation's authority ceiling"
            );
            return Err(TokenError::ScopedTokenForbidden {
                profile: prepared.profile_name.to_owned(),
                source_profile: prepared.source_name.to_owned(),
                source,
            });
        }
        Err(source) => {
            tracing::debug!(
                source_profile = prepared.source_name,
                error = %source,
                "GitHub scoped token request failed"
            );
            return Err(TokenError::GitHub(source));
        }
    };
    let received_at = now();
    let IssuedScopedToken {
        access_token,
        expires_at,
    } = response;
    match validate_scoped_expiry(expires_at.as_deref(), received_at) {
        Ok(expires_at) => {
            tracing::debug!(
                source_profile = prepared.source_name,
                expires_at = %expires_at,
                "validated scoped token lifetime"
            );
            Ok(ValidatedScopedToken {
                access_token,
                expires_at,
                received_at,
            })
        }
        Err(error) => {
            tracing::debug!(
                source_profile = prepared.source_name,
                error = %error,
                "issued scoped token had an invalid lifetime"
            );
            Err(revoke_with_context(
                client,
                &prepared.app.as_registration(),
                &access_token,
                error,
            ))
        }
    }
}

fn permanent_rejection_error<S, E>(store: &S, prepared: &PreparedScopedToken<'_>) -> TokenError<E>
where
    S: WriteCredentials<Error = E>,
    E: std::error::Error + 'static,
{
    let source_profile = prepared.source_name;
    let generation = prepared.base.generation_fingerprint();
    let outcome = match store.delete_base_if_generation(source_profile, &generation) {
        Ok(outcome) => outcome,
        Err(error) => return TokenError::Storage(error),
    };
    match outcome {
        DeleteBaseOutcome::Deleted => tracing::warn!(
            source_profile,
            "evicted cached base token after GitHub permanently rejected it"
        ),
        DeleteBaseOutcome::Missing => tracing::debug!(
            source_profile,
            "rejected base token was already removed while minting"
        ),
        DeleteBaseOutcome::Changed => {
            tracing::debug!(
                source_profile,
                "rejected base token was replaced while minting"
            );
            return TokenError::BaseGenerationChanged(source_profile.to_owned());
        }
    }
    TokenError::NoSourceBaseTokenCached(source_profile.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::store::{
        CommitBaseOutcome, CommitScopedOutcome, DeleteBaseOutcome, IssuanceGuard,
        IssuanceGuardStore, ReadCredentials, ReplaceOutcome, SourceGuard, WriteCredentials,
    };
    use crate::credential::{
        AccessToken, BaseCredential, ScopedCredential, TokenExpiry, authority_fingerprint,
    };
    use crate::domain::profile::AppAuthority;
    use crate::repository::RepositorySelection;
    use crate::token::{IssuedScopedToken, RemoteError, RevokeTokenClient, ScopedTokenClient};
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicU64, Ordering};
    use time::Duration;

    #[derive(Debug)]
    struct MockStoreError;

    impl std::fmt::Display for MockStoreError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "mock store error")
        }
    }

    impl std::error::Error for MockStoreError {}

    struct FakeStore {
        events: RefCell<Vec<&'static str>>,
        base_expiry: Option<TokenExpiry>,
        scoped_commits: RefCell<Vec<String>>,
        base_deletions: RefCell<Vec<String>>,
        guard_counter: AtomicU64,
    }

    impl FakeStore {
        fn new(base_expiry: Option<TokenExpiry>) -> Self {
            Self {
                events: RefCell::new(Vec::new()),
                base_expiry,
                scoped_commits: RefCell::new(Vec::new()),
                base_deletions: RefCell::new(Vec::new()),
                guard_counter: AtomicU64::new(1),
            }
        }
    }

    impl ReadCredentials for FakeStore {
        type Error = MockStoreError;

        fn read_base(&self, profile: &str) -> Result<Option<BaseCredential>, Self::Error> {
            self.events.borrow_mut().push("read_base");
            if profile == "developer" {
                Ok(self.base_expiry.map(sample_base))
            } else {
                Ok(None)
            }
        }

        fn read_scoped(
            &self,
            _profile: &str,
            _canonical_scope: &str,
        ) -> Result<Option<ScopedCredential>, Self::Error> {
            self.events.borrow_mut().push("read_scoped");
            Ok(None)
        }
    }

    impl WriteCredentials for FakeStore {
        type Error = MockStoreError;

        fn commit_base(
            &self,
            _candidate: &BaseCredential,
            _guard: IssuanceGuard,
        ) -> Result<CommitBaseOutcome, Self::Error> {
            self.events.borrow_mut().push("commit_base");
            Ok(CommitBaseOutcome::Saved)
        }

        fn commit_scoped(
            &self,
            candidate: &ScopedCredential,
            _guard: IssuanceGuard,
            _source_guard: &SourceGuard<'_>,
        ) -> Result<CommitScopedOutcome, Self::Error> {
            self.events.borrow_mut().push("commit_scoped");
            self.scoped_commits
                .borrow_mut()
                .push(candidate.profile.clone());
            Ok(CommitScopedOutcome::Saved)
        }

        fn renew_scoped(
            &self,
            _expected: &ScopedCredential,
            _candidate: &ScopedCredential,
            _guard: IssuanceGuard,
            _source_guard: &SourceGuard<'_>,
            _now: OffsetDateTime,
        ) -> Result<ReplaceOutcome<ScopedCredential>, Self::Error> {
            self.events.borrow_mut().push("renew_scoped");
            Ok(ReplaceOutcome::EpochChanged)
        }

        fn delete_base_if_generation(
            &self,
            source_profile: &str,
            _expected_generation: &str,
        ) -> Result<DeleteBaseOutcome, Self::Error> {
            self.events.borrow_mut().push("delete_base");
            self.base_deletions
                .borrow_mut()
                .push(source_profile.to_string());
            Ok(DeleteBaseOutcome::Deleted)
        }
    }

    impl IssuanceGuardStore for FakeStore {
        type Error = MockStoreError;

        fn issuance_guard(&self) -> Result<IssuanceGuard, Self::Error> {
            self.events.borrow_mut().push("issuance_guard");
            let id = self.guard_counter.fetch_add(1, Ordering::SeqCst);
            Ok(IssuanceGuard::new(id))
        }
    }

    struct FakeClient {
        events: RefCell<Vec<&'static str>>,
        response: RefCell<Option<Result<IssuedScopedToken, RemoteError>>>,
        revoked: RefCell<Vec<String>>,
    }

    impl FakeClient {
        fn new(response: Result<IssuedScopedToken, RemoteError>) -> Self {
            Self {
                events: RefCell::new(Vec::new()),
                response: RefCell::new(Some(response)),
                revoked: RefCell::new(Vec::new()),
            }
        }
    }

    impl ScopedTokenClient for FakeClient {
        fn create_scoped_token(
            &self,
            _request: &ScopedTokenRequest<'_>,
        ) -> Result<IssuedScopedToken, RemoteError> {
            self.events.borrow_mut().push("create_scoped_token");
            self.response
                .borrow_mut()
                .take()
                .expect("response already taken")
        }
    }

    impl RevokeTokenClient for FakeClient {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            access_token: &str,
        ) -> Result<(), RemoteError> {
            self.events.borrow_mut().push("delete_token");
            self.revoked.borrow_mut().push(access_token.to_string());
            Ok(())
        }
    }

    fn sample_base(expires_at: TokenExpiry) -> BaseCredential {
        BaseCredential {
            profile: "developer".into(),
            authority_fingerprint: authority_fingerprint("client-123", "acme-corp"),
            github_user: "octocat".into(),
            expires_at,
            access_token: AccessToken::from("base-secret-tok"),
        }
    }

    fn repos_all() -> RepositorySelection {
        RepositorySelection::resolve(
            &[],
            &crate::domain::profile::RepoScope::All,
            "acme-corp",
            || unreachable!(),
        )
        .unwrap()
    }

    #[test]
    fn test_fresh_scoped_token_and_request_debug_redacts_secrets() {
        let secret = "top-secret-app-client-secret-999";
        let access_tok = "ghu_secret_access_token_123456789";
        let authority = AppAuthority {
            account: "acme-corp",
            client_id: "client-123",
        };
        let app = AppCredentials {
            authority,
            client_secret: secret,
        };
        let repos = repos_all();
        let perms = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);

        let req = FreshScopedTokenRequest {
            profile_name: "dev-scoped",
            source_name: "developer",
            app,
            repository_selection: &repos,
            permissions: &perms,
        };
        let req_debug = format!("{req:?}");
        assert!(!req_debug.contains(secret));
        assert!(req_debug.contains("[REDACTED]"));
        assert!(req_debug.contains("dev-scoped"));

        let token = FreshScopedToken {
            access_token: AccessToken::from(access_tok),
            expires_at: TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(1)),
            github_user: "octocat".into(),
            repo_scope: "all".into(),
            profile: "dev-scoped".into(),
            source_profile: "developer".into(),
            source_authority_fingerprint: "fp".into(),
            issuance_guard: IssuanceGuard::new(42),
            expected_base_generation: "gen".into(),
        };
        let token_debug = format!("{token:?}");
        assert!(!token_debug.contains(access_tok));
        assert!(token_debug.contains("[REDACTED]"));
        assert!(token_debug.contains("octocat"));
    }

    #[test]
    fn test_issue_fresh_scoped_success_call_order_and_no_reusable_storage() {
        let now = OffsetDateTime::now_utc();
        let expiry = TokenExpiry::new(now + Duration::hours(2));
        let expected_generation = sample_base(expiry).generation_fingerprint();
        let store = FakeStore::new(Some(expiry));
        let client = FakeClient::new(Ok(IssuedScopedToken {
            access_token: AccessToken::from("issued-token"),
            expires_at: Some(
                (now + Duration::hours(1))
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap(),
            ),
        }));

        let authority = AppAuthority {
            account: "acme-corp",
            client_id: "client-123",
        };
        let app = AppCredentials {
            authority,
            client_secret: "secret",
        };
        let repos = repos_all();
        let perms = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);
        let req = FreshScopedTokenRequest {
            profile_name: "reader",
            source_name: "developer",
            app,
            repository_selection: &repos,
            permissions: &perms,
        };

        let result = issue_fresh_scoped(&client, &store, &req, || now).unwrap();

        // Check call order: read_base -> issuance_guard -> create_scoped_token
        assert_eq!(*store.events.borrow(), vec!["read_base", "issuance_guard"]);
        assert_eq!(*client.events.borrow(), vec!["create_scoped_token"]);

        // Guard and generation match base used
        assert_eq!(result.expected_base_generation, expected_generation);
        assert_eq!(result.issuance_guard, IssuanceGuard::new(1));
        assert_eq!(result.access_token.as_ref(), "issued-token");

        // Crucial invariant: NOT persisted as reusable scoped token!
        assert!(store.scoped_commits.borrow().is_empty());
    }

    #[test]
    fn test_issue_fresh_scoped_base_inside_margin_rejected_without_network() {
        let now = OffsetDateTime::now_utc();
        // Expiry inside 30s handoff margin (e.g. now + 10s)
        let store = FakeStore::new(Some(TokenExpiry::new(now + Duration::seconds(10))));
        let client = FakeClient::new(Ok(IssuedScopedToken {
            access_token: AccessToken::from("should-not-be-issued"),
            expires_at: None,
        }));

        let authority = AppAuthority {
            account: "acme-corp",
            client_id: "client-123",
        };
        let app = AppCredentials {
            authority,
            client_secret: "secret",
        };
        let repos = repos_all();
        let perms = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);
        let req = FreshScopedTokenRequest {
            profile_name: "reader",
            source_name: "developer",
            app,
            repository_selection: &repos,
            permissions: &perms,
        };

        let err = issue_fresh_scoped(&client, &store, &req, || now).unwrap_err();
        assert!(matches!(err, TokenError::NoSourceBaseTokenCached(ref s) if s == "developer"));

        // No network call made
        assert!(client.events.borrow().is_empty());
        assert!(store.scoped_commits.borrow().is_empty());
    }

    #[test]
    fn test_issue_fresh_scoped_permanent_rejection_evicts_base() {
        for status in [401, 404] {
            let now = OffsetDateTime::now_utc();
            let store = FakeStore::new(Some(TokenExpiry::new(now + Duration::hours(2))));
            let client = FakeClient::new(Err(RemoteError::Http {
                status,
                message: "Unauthorized".into(),
            }));

            let authority = AppAuthority {
                account: "acme-corp",
                client_id: "client-123",
            };
            let app = AppCredentials {
                authority,
                client_secret: "secret",
            };
            let repos = repos_all();
            let perms = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);
            let req = FreshScopedTokenRequest {
                profile_name: "reader",
                source_name: "developer",
                app,
                repository_selection: &repos,
                permissions: &perms,
            };

            let err = issue_fresh_scoped(&client, &store, &req, || now).unwrap_err();
            assert!(matches!(err, TokenError::NoSourceBaseTokenCached(_)));
            assert_eq!(*store.base_deletions.borrow(), vec!["developer"]);
        }
    }

    #[test]
    fn test_issue_fresh_scoped_403_returns_forbidden() {
        let now = OffsetDateTime::now_utc();
        let store = FakeStore::new(Some(TokenExpiry::new(now + Duration::hours(2))));
        let client = FakeClient::new(Err(RemoteError::Http {
            status: 403,
            message: "Forbidden".into(),
        }));

        let authority = AppAuthority {
            account: "acme-corp",
            client_id: "client-123",
        };
        let app = AppCredentials {
            authority,
            client_secret: "secret",
        };
        let repos = repos_all();
        let perms = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);
        let req = FreshScopedTokenRequest {
            profile_name: "reader",
            source_name: "developer",
            app,
            repository_selection: &repos,
            permissions: &perms,
        };

        let err = issue_fresh_scoped(&client, &store, &req, || now).unwrap_err();
        assert!(matches!(err, TokenError::ScopedTokenForbidden { .. }));
        assert!(store.base_deletions.borrow().is_empty());
    }

    #[test]
    fn test_issue_fresh_scoped_invalid_lifetime_revokes_candidate() {
        let now = OffsetDateTime::now_utc();
        let store = FakeStore::new(Some(TokenExpiry::new(now + Duration::hours(2))));
        // Missing expires_at or expired timestamp
        let client = FakeClient::new(Ok(IssuedScopedToken {
            access_token: AccessToken::from("invalid-token"),
            expires_at: Some("not-a-timestamp".into()),
        }));

        let authority = AppAuthority {
            account: "acme-corp",
            client_id: "client-123",
        };
        let app = AppCredentials {
            authority,
            client_secret: "secret",
        };
        let repos = repos_all();
        let perms = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);
        let req = FreshScopedTokenRequest {
            profile_name: "reader",
            source_name: "developer",
            app,
            repository_selection: &repos,
            permissions: &perms,
        };

        let err = issue_fresh_scoped(&client, &store, &req, || now).unwrap_err();
        assert!(matches!(err, TokenError::InvalidLifetime { .. }));
        assert_eq!(*client.revoked.borrow(), vec!["invalid-token"]);
        assert!(store.scoped_commits.borrow().is_empty());
    }
}
