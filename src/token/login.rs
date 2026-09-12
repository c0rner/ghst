use super::base::{load_valid_base_status, persist_base_response};
use super::device_flow::{DeviceFlow, DeviceFlowError};
use super::types::BasePersistence;
use super::{BaseTokenClient, DeviceFlowClient, TokenError};
use crate::credential::store::{IssuanceGuardStore, ReadCredentials, WriteCredentials};
use crate::profile::NamedAppRegistration;
use crate::token::{BaseTokenStatus, RemoteError};
use std::fmt;
use std::time::Duration;
use time::OffsetDateTime;

/// The non-secret subset of a GitHub device authorization shown to the user.
pub struct AuthorizationPrompt<'a> {
    pub target_account: &'a str,
    pub user_code: &'a str,
    pub verification_uri: &'a str,
}

/// Presents device authorization instructions without receiving OAuth secrets.
pub trait PresentAuthorization {
    fn present(&self, prompt: AuthorizationPrompt<'_>);
}

pub enum LoginOutcome {
    Authenticated(BaseTokenStatus),
    AlreadyAuthenticated(BaseTokenStatus),
}

#[derive(Debug)]
pub enum LoginError<E> {
    Token(TokenError<E>),
    IssuanceGuard(E),
    Remote(RemoteError),
    Expired,
    AccessDenied,
}

impl<E: fmt::Display> fmt::Display for LoginError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token(error) => error.fmt(f),
            Self::IssuanceGuard(error) => write!(f, "failed to capture issuance guard: {error}"),
            Self::Remote(error) => error.fmt(f),
            Self::Expired => write!(f, "device code expired"),
            Self::AccessDenied => write!(f, "authorization request was denied"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for LoginError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Token(error) => Some(error),
            Self::IssuanceGuard(error) => Some(error),
            Self::Remote(error) => Some(error),
            Self::Expired | Self::AccessDenied => None,
        }
    }
}

/// Authenticates an app profile using the GitHub OAuth Device Flow.
pub fn authenticate<C, S, P, E>(
    client: &C,
    store: &S,
    presenter: &P,
    app: NamedAppRegistration<'_>,
) -> Result<LoginOutcome, LoginError<E>>
where
    C: DeviceFlowClient + BaseTokenClient,
    S: ReadCredentials<Error = E> + IssuanceGuardStore<Error = E> + WriteCredentials<Error = E>,
    P: PresentAuthorization,
    E: std::error::Error + 'static,
{
    authenticate_with_io(
        client,
        store,
        presenter,
        app,
        OffsetDateTime::now_utc,
        std::thread::sleep,
    )
}

fn authenticate_with_io<C, S, P, E, N, Sl>(
    client: &C,
    store: &S,
    presenter: &P,
    app: NamedAppRegistration<'_>,
    mut now: N,
    sleep: Sl,
) -> Result<LoginOutcome, LoginError<E>>
where
    C: DeviceFlowClient + BaseTokenClient,
    S: ReadCredentials<Error = E> + IssuanceGuardStore<Error = E> + WriteCredentials<Error = E>,
    P: PresentAuthorization,
    E: std::error::Error + 'static,
    N: FnMut() -> OffsetDateTime,
    Sl: FnMut(Duration),
{
    tracing::debug!(
        profile = app.profile_name,
        "checking for a reusable cached base token"
    );
    if let Some(status) = load_valid_base_status(store, app.profile_name, &app.app.authority, now())
        .map_err(LoginError::Token)?
    {
        tracing::debug!(
            profile = app.profile_name,
            github_user = status.github_user,
            expires_at = %status.expires_at,
            "reusing cached base token"
        );
        return Ok(LoginOutcome::AlreadyAuthenticated(status));
    }

    let guard = store.issuance_guard().map_err(LoginError::IssuanceGuard)?;
    tracing::info!(profile = app.profile_name, "initiating OAuth Device Flow");
    let mut flow = DeviceFlow::new(client, sleep, app.profile_name);
    let authorization = flow
        .request_authorization(app.app.authority.client_id)
        .map_err(map_device_flow_error)?;
    tracing::debug!(
        profile = app.profile_name,
        expires_in_seconds = authorization.expires_in.as_secs(),
        poll_interval_seconds = authorization.interval.as_secs(),
        "device authorization request created"
    );
    presenter.present(AuthorizationPrompt {
        target_account: app.app.authority.account,
        user_code: &authorization.user_code,
        verification_uri: &authorization.verification_uri,
    });
    let response = flow
        .poll_authorization(app.app.authority.client_id, &authorization)
        .map_err(map_device_flow_error)?;
    tracing::debug!(
        profile = app.profile_name,
        "device authorization completed; validating and caching base token"
    );
    persist_base_response(
        client,
        &app.app,
        app.profile_name,
        store,
        response,
        now(),
        guard,
    )
    .map(|result| match result {
        BasePersistence::Saved(status) => {
            tracing::debug!(
                profile = app.profile_name,
                expires_at = %status.expires_at,
                "cached new base token"
            );
            LoginOutcome::Authenticated(status)
        }
        BasePersistence::Retained(status) => {
            tracing::debug!(
                profile = app.profile_name,
                expires_at = %status.expires_at,
                "retained compatible base token cached by a concurrent login"
            );
            LoginOutcome::AlreadyAuthenticated(status)
        }
    })
    .map_err(LoginError::Token)
}

fn map_device_flow_error<E>(error: DeviceFlowError) -> LoginError<E> {
    match error {
        DeviceFlowError::Remote(error) => LoginError::Remote(error),
        DeviceFlowError::Expired => LoginError::Expired,
        DeviceFlowError::AccessDenied => LoginError::AccessDenied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::store::{
        CommitBaseOutcome, CommitScopedOutcome, DeleteBaseOutcome, IssuanceGuard, ReplaceOutcome,
        SourceGuard,
    };
    use crate::credential::{AccessToken, BaseCredential, TokenExpiry, authority_fingerprint};
    use crate::profile::{AppAuthority, AppRegistration};
    use crate::token::{
        DeviceAuthorization, DeviceFlowPoll, GitHubUser, IssuedBaseToken, RevokeTokenClient,
    };
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;
    use zeroize::Zeroizing;

    type TestError = std::io::Error;

    #[derive(Clone, Default)]
    struct Trace(Rc<RefCell<Vec<&'static str>>>);

    impl Trace {
        fn add(&self, event: &'static str) {
            self.0.borrow_mut().push(event);
        }
    }

    struct Client {
        trace: Trace,
        polls: RefCell<VecDeque<Result<DeviceFlowPoll, RemoteError>>>,
        request_error: bool,
        revoked: RefCell<Vec<String>>,
    }

    impl DeviceFlowClient for Client {
        fn request_device_code(&self, _: &str) -> Result<DeviceAuthorization, RemoteError> {
            self.trace.add("request");
            if self.request_error {
                return Err(RemoteError::Transport(std::io::Error::other("offline")));
            }
            Ok(DeviceAuthorization {
                device_code: Zeroizing::new("device-secret".into()),
                user_code: "ABCD-EFGH".into(),
                verification_uri: "https://github.com/login/device".into(),
                expires_in: Duration::from_mins(15),
                interval: Duration::from_secs(5),
            })
        }

        fn poll_access_token(&self, _: &str, _: &str) -> Result<DeviceFlowPoll, RemoteError> {
            self.trace.add("poll");
            self.polls.borrow_mut().pop_front().unwrap()
        }
    }

    impl RevokeTokenClient for Client {
        fn delete_token(&self, _: &str, _: &str, _: &str) -> Result<(), RemoteError> {
            self.revoked.borrow_mut().push("unused".into());
            Ok(())
        }
    }

    impl BaseTokenClient for Client {
        fn get_user(&self, _: &str) -> Result<GitHubUser, RemoteError> {
            self.trace.add("identify");
            Ok(GitHubUser {
                login: "octocat".into(),
            })
        }
    }

    struct Store {
        trace: Trace,
        base: RefCell<Option<BaseCredential>>,
        guard_error: bool,
        retain_commit: bool,
    }

    impl ReadCredentials for Store {
        type Error = TestError;

        fn read_base(&self, _: &str) -> Result<Option<BaseCredential>, Self::Error> {
            self.trace.add("read");
            Ok(self.base.borrow_mut().take())
        }

        fn read_scoped(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<crate::credential::ScopedCredential>, Self::Error> {
            unreachable!()
        }
    }

    impl IssuanceGuardStore for Store {
        type Error = TestError;

        fn issuance_guard(&self) -> Result<IssuanceGuard, Self::Error> {
            self.trace.add("guard");
            if self.guard_error {
                Err(std::io::Error::other("guard failed"))
            } else {
                Ok(IssuanceGuard::new(1))
            }
        }
    }

    impl WriteCredentials for Store {
        type Error = TestError;

        fn commit_base(
            &self,
            _: &BaseCredential,
            _: IssuanceGuard,
        ) -> Result<CommitBaseOutcome, Self::Error> {
            self.trace.add("commit");
            if self.retain_commit {
                Ok(CommitBaseOutcome::Retained(BaseCredential {
                    profile: "developer".into(),
                    authority_fingerprint: authority_fingerprint("client-id", "acme"),
                    github_user: "concurrent".into(),
                    expires_at: TokenExpiry::new(
                        OffsetDateTime::UNIX_EPOCH + time::Duration::hours(2),
                    ),
                    access_token: AccessToken::from("concurrent-token"),
                }))
            } else {
                Ok(CommitBaseOutcome::Saved)
            }
        }

        fn commit_scoped(
            &self,
            _: &crate::credential::ScopedCredential,
            _: IssuanceGuard,
            _: &SourceGuard<'_>,
        ) -> Result<CommitScopedOutcome, Self::Error> {
            unreachable!()
        }
        fn renew_scoped(
            &self,
            _: &crate::credential::ScopedCredential,
            _: &crate::credential::ScopedCredential,
            _: IssuanceGuard,
            _: &SourceGuard<'_>,
            _: OffsetDateTime,
        ) -> Result<ReplaceOutcome<crate::credential::ScopedCredential>, Self::Error> {
            unreachable!()
        }
        fn delete_base_if_generation(
            &self,
            _: &str,
            _: &str,
        ) -> Result<DeleteBaseOutcome, Self::Error> {
            unreachable!()
        }
    }

    struct Presenter(Trace);
    impl PresentAuthorization for Presenter {
        fn present(&self, prompt: AuthorizationPrompt<'_>) {
            assert_eq!(
                (prompt.target_account, prompt.user_code),
                ("acme", "ABCD-EFGH")
            );
            self.0.add("present");
        }
    }

    struct CapturedPrompt(Rc<RefCell<Option<(String, String, String)>>>);

    impl PresentAuthorization for CapturedPrompt {
        fn present(&self, prompt: AuthorizationPrompt<'_>) {
            *self.0.borrow_mut() = Some((
                prompt.target_account.into(),
                prompt.user_code.into(),
                prompt.verification_uri.into(),
            ));
        }
    }

    fn app() -> NamedAppRegistration<'static> {
        NamedAppRegistration {
            profile_name: "developer",
            app: AppRegistration {
                authority: AppAuthority {
                    account: "acme",
                    client_id: "client-id",
                },
                client_secret: Some("client-secret"),
            },
        }
    }

    fn issued() -> IssuedBaseToken {
        IssuedBaseToken {
            access_token: AccessToken::from("issued-token"),
            expires_in: Some(3_600),
        }
    }

    fn make_client(trace: Trace, polls: Vec<Result<DeviceFlowPoll, RemoteError>>) -> Client {
        Client {
            trace,
            polls: RefCell::new(VecDeque::from(polls)),
            request_error: false,
            revoked: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn workflow_prompt_excludes_device_secret() {
        let trace = Trace::default();
        let store = Store {
            trace: trace.clone(),
            base: RefCell::new(None),
            guard_error: false,
            retain_commit: false,
        };
        let client = make_client(trace, vec![Ok(DeviceFlowPoll::Authorized(issued()))]);
        let captured = Rc::new(RefCell::new(None));
        let presenter = CapturedPrompt(captured.clone());
        authenticate_with_io(
            &client,
            &store,
            &presenter,
            app(),
            || OffsetDateTime::UNIX_EPOCH,
            |_| {},
        )
        .unwrap();
        let captured = captured.borrow().clone().expect("prompt was presented");
        assert_eq!(
            captured,
            (
                "acme".into(),
                "ABCD-EFGH".into(),
                "https://github.com/login/device".into()
            )
        );
        assert!(!format!("{captured:?}").contains("device-secret"));
    }

    #[test]
    fn cache_hit_skips_guard_and_device_flow() {
        let trace = Trace::default();
        let store = Store {
            trace: trace.clone(),
            base: RefCell::new(Some(BaseCredential {
                profile: "developer".into(),
                authority_fingerprint: authority_fingerprint("client-id", "acme"),
                github_user: "octocat".into(),
                expires_at: TokenExpiry::new(OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1)),
                access_token: AccessToken::from("cached-token"),
            })),
            guard_error: true,
            retain_commit: false,
        };
        let client = make_client(trace.clone(), Vec::new());
        let presenter = Presenter(trace.clone());
        let result = authenticate_with_io(
            &client,
            &store,
            &presenter,
            app(),
            || OffsetDateTime::UNIX_EPOCH,
            |_| panic!("must not sleep"),
        )
        .unwrap();
        assert!(matches!(result, LoginOutcome::AlreadyAuthenticated(_)));
        assert_eq!(&*trace.0.borrow(), &["read"]);
    }

    #[test]
    fn cache_miss_orders_guard_prompt_poll_identify_and_commit() {
        let trace = Trace::default();
        let store = Store {
            trace: trace.clone(),
            base: RefCell::new(None),
            guard_error: false,
            retain_commit: false,
        };
        let client = make_client(
            trace.clone(),
            vec![Ok(DeviceFlowPoll::Authorized(issued()))],
        );
        let presenter = Presenter(trace.clone());
        let mut times = VecDeque::from([OffsetDateTime::UNIX_EPOCH, OffsetDateTime::UNIX_EPOCH]);
        let result = authenticate_with_io(
            &client,
            &store,
            &presenter,
            app(),
            || times.pop_front().unwrap(),
            |_| trace.add("sleep"),
        )
        .unwrap();
        assert!(matches!(result, LoginOutcome::Authenticated(_)));
        assert_eq!(
            &*trace.0.borrow(),
            &[
                "read", "guard", "request", "present", "sleep", "poll", "identify", "commit"
            ]
        );
    }

    #[test]
    fn response_receipt_time_is_used_for_base_lifetime_validation() {
        let trace = Trace::default();
        let store = Store {
            trace: trace.clone(),
            base: RefCell::new(None),
            guard_error: false,
            retain_commit: false,
        };
        let client = make_client(
            trace.clone(),
            vec![Ok(DeviceFlowPoll::Authorized(issued()))],
        );
        let presenter = Presenter(trace);
        let receipt = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(2);
        let mut times = VecDeque::from([OffsetDateTime::UNIX_EPOCH, receipt]);
        let LoginOutcome::Authenticated(status) = authenticate_with_io(
            &client,
            &store,
            &presenter,
            app(),
            || times.pop_front().unwrap(),
            |_| {},
        )
        .unwrap() else {
            panic!("expected saved credential")
        };
        assert_eq!(
            status.expires_at,
            TokenExpiry::new(receipt + time::Duration::seconds(3_600))
        );
    }

    #[test]
    fn expiry_and_denial_do_not_identify_or_commit() {
        for expired in [true, false] {
            let terminal = if expired {
                DeviceFlowPoll::Expired
            } else {
                DeviceFlowPoll::AccessDenied
            };
            let trace = Trace::default();
            let store = Store {
                trace: trace.clone(),
                base: RefCell::new(None),
                guard_error: false,
                retain_commit: false,
            };
            let client = make_client(trace.clone(), vec![Ok(terminal)]);
            let presenter = Presenter(trace.clone());
            let result = authenticate_with_io(
                &client,
                &store,
                &presenter,
                app(),
                || OffsetDateTime::UNIX_EPOCH,
                |_| {},
            );
            assert!(matches!(
                (expired, result),
                (true, Err(LoginError::Expired)) | (false, Err(LoginError::AccessDenied))
            ));
            assert_eq!(
                &*trace.0.borrow(),
                &["read", "guard", "request", "present", "poll"]
            );
        }
    }

    #[test]
    fn guard_failure_precedes_device_request_and_presentation() {
        let trace = Trace::default();
        let store = Store {
            trace: trace.clone(),
            base: RefCell::new(None),
            guard_error: true,
            retain_commit: false,
        };
        let client = make_client(trace.clone(), Vec::new());
        let presenter = Presenter(trace.clone());
        let result = authenticate_with_io(
            &client,
            &store,
            &presenter,
            app(),
            || OffsetDateTime::UNIX_EPOCH,
            |_| {},
        );
        assert!(matches!(result, Err(LoginError::IssuanceGuard(_))));
        assert_eq!(&*trace.0.borrow(), &["read", "guard"]);
    }

    #[test]
    fn device_request_and_poll_failures_stop_before_later_steps() {
        let trace = Trace::default();
        let store = Store {
            trace: trace.clone(),
            base: RefCell::new(None),
            guard_error: false,
            retain_commit: false,
        };
        let mut client = make_client(trace.clone(), Vec::new());
        client.request_error = true;
        let presenter = Presenter(trace.clone());
        let result = authenticate_with_io(
            &client,
            &store,
            &presenter,
            app(),
            || OffsetDateTime::UNIX_EPOCH,
            |_| {},
        );
        assert!(matches!(
            result,
            Err(LoginError::Remote(RemoteError::Transport(_)))
        ));
        assert_eq!(&*trace.0.borrow(), &["read", "guard", "request"]);

        let trace = Trace::default();
        let store = Store {
            trace: trace.clone(),
            base: RefCell::new(None),
            guard_error: false,
            retain_commit: false,
        };
        let client = make_client(
            trace.clone(),
            vec![Err(RemoteError::Protocol { context: "poll" })],
        );
        let presenter = Presenter(trace.clone());
        let result = authenticate_with_io(
            &client,
            &store,
            &presenter,
            app(),
            || OffsetDateTime::UNIX_EPOCH,
            |_| {},
        );
        assert!(matches!(
            result,
            Err(LoginError::Remote(RemoteError::Protocol {
                context: "poll"
            }))
        ));
        assert_eq!(
            &*trace.0.borrow(),
            &["read", "guard", "request", "present", "poll"]
        );
    }

    #[test]
    fn compatible_concurrent_winner_is_returned_and_unused_candidate_is_cleaned_up() {
        let trace = Trace::default();
        let store = Store {
            trace: trace.clone(),
            base: RefCell::new(None),
            guard_error: false,
            retain_commit: true,
        };
        let client = make_client(
            trace.clone(),
            vec![Ok(DeviceFlowPoll::Authorized(issued()))],
        );
        let presenter = Presenter(trace);
        let result = authenticate_with_io(
            &client,
            &store,
            &presenter,
            app(),
            || OffsetDateTime::UNIX_EPOCH,
            |_| {},
        )
        .unwrap();
        let LoginOutcome::AlreadyAuthenticated(status) = result else {
            panic!("expected retained winner")
        };
        assert_eq!(status.github_user, "concurrent");
        assert_eq!(client.revoked.borrow().as_slice(), &["unused"]);
    }
}
