use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::{self, Write as _};
use time::OffsetDateTime;

use super::cleanup::cleanup_marked_run_with_app;
use super::process::{
    ActiveSignals, ChildProcess, PreparedSignals, ProcessExit, SignalForwarding, SpawnProcess,
    SpawnRequest,
};
use super::store::{PendingRunOutcome, PendingRunStore, RunLifecycleStore};
use super::{RunRecord, RunState};
use crate::credential::AccessToken;
use crate::credential::store::{
    IssuanceGuardStore, ReadCredentials, SourceGuard, WriteCredentials,
};
use crate::profile::{AppCredentials, PermissionLevel};
use crate::repository::RepositorySelection;
use crate::token::{
    FreshScopedTokenRequest, RevokeTokenClient, ScopedTokenClient, TokenError, issue_fresh_scoped,
    revoke_with_context,
};

/// High-level request specifying scoped token parameters and child execution details.
pub struct RunRequest<'a> {
    pub profile_name: &'a str,
    pub source_name: &'a str,
    pub app: AppCredentials<'a>,
    pub permissions: &'a BTreeMap<String, PermissionLevel>,
    pub repositories: &'a RepositorySelection,
    pub wrapper_pid: u32,
    pub command: &'a [OsString],
}

impl fmt::Debug for RunRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunRequest")
            .field("profile_name", &self.profile_name)
            .field("source_name", &self.source_name)
            .field("app", &self.app)
            .field("permissions", &self.permissions)
            .field("wrapper_pid", &self.wrapper_pid)
            .field("command_len", &self.command.len())
            .finish()
    }
}

/// Status of background cleanup after run termination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupStatus {
    Complete,
    Incomplete,
}

impl CleanupStatus {
    #[inline]
    pub const fn is_incomplete(self) -> bool {
        matches!(self, Self::Incomplete)
    }
}

/// Result of running a child process to completion after successful activation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Execution {
    pub exit_code: ProcessExit,
    pub cleanup: CleanupStatus,
}

/// Error encountered before the child process transitions to running.
#[derive(Debug)]
pub enum ExecuteError<E, P> {
    InvalidCommand,
    Token(TokenError<E>),
    PrepareSignals { source: P, cleanup: CleanupStatus },
    Spawn { source: P, cleanup: CleanupStatus },
    StartForwarding { source: P, cleanup: CleanupStatus },
    Activation { source: E, cleanup: CleanupStatus },
}

impl<E, P> ExecuteError<E, P> {
    pub const fn cleanup_status(&self) -> Option<CleanupStatus> {
        match self {
            Self::InvalidCommand | Self::Token(_) => None,
            Self::PrepareSignals { cleanup, .. }
            | Self::Spawn { cleanup, .. }
            | Self::StartForwarding { cleanup, .. }
            | Self::Activation { cleanup, .. } => Some(*cleanup),
        }
    }
}

impl<E: fmt::Display, P: fmt::Display> fmt::Display for ExecuteError<E, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCommand => write!(f, "command must not be empty"),
            Self::Token(err) => write!(f, "{err}"),
            Self::PrepareSignals { source, .. } => {
                write!(f, "failed to prepare signal handling: {source}")
            }
            Self::Spawn { source, .. } => write!(f, "failed to spawn child process: {source}"),
            Self::StartForwarding { source, .. } => {
                write!(f, "failed to start signal forwarding: {source}")
            }
            Self::Activation { source, .. } => write!(f, "failed to activate run: {source}"),
        }
    }
}

impl<E, P> std::error::Error for ExecuteError<E, P>
where
    E: std::error::Error + 'static,
    P: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidCommand => None,
            Self::Token(err) => Some(err),
            Self::PrepareSignals { source, .. }
            | Self::Spawn { source, .. }
            | Self::StartForwarding { source, .. } => Some(source),
            Self::Activation { source, .. } => Some(source),
        }
    }
}

struct RunIdentity {
    run_id: String,
    wrapper_pid: u32,
}

struct PendingRun {
    identity: RunIdentity,
    access_token: AccessToken,
}

impl fmt::Debug for PendingRun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingRun")
            .field("run_id", &self.identity.run_id)
            .field("wrapper_pid", &self.identity.wrapper_pid)
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

struct ActiveRun {
    identity: RunIdentity,
    child_pid: u32,
}

impl PendingRun {
    fn access_token(&self) -> &str {
        self.access_token.as_ref()
    }

    fn activate<S, E>(self, store: &S, child_pid: u32) -> Result<ActiveRun, (E, Self)>
    where
        S: RunLifecycleStore<Error = E>,
    {
        match store.activate(&self.identity.run_id, self.identity.wrapper_pid, child_pid) {
            Ok(_) => Ok(ActiveRun {
                identity: self.identity,
                child_pid,
            }),
            Err(err) => Err((err, self)),
        }
    }

    fn abort<C, S, E>(
        self,
        client: &C,
        app: &AppCredentials<'_>,
        source_name: &str,
        store: &S,
        child_pid: Option<u32>,
    ) -> CleanupStatus
    where
        C: RevokeTokenClient,
        S: RunLifecycleStore<Error = E>,
        E: fmt::Debug + fmt::Display,
    {
        match store.abort(&self.identity.run_id, self.identity.wrapper_pid, child_pid) {
            Ok(entry) => {
                let report = cleanup_marked_run_with_app(client, app, source_name, store, &entry);
                if report.is_complete() {
                    CleanupStatus::Complete
                } else {
                    CleanupStatus::Incomplete
                }
            }
            Err(err) => {
                tracing::debug!(error = %err, "failed to transition pending run to cleanup pending on abort");
                CleanupStatus::Incomplete
            }
        }
    }
}

impl ActiveRun {
    fn finish<C, S, E>(
        self,
        client: &C,
        app: &AppCredentials<'_>,
        source_name: &str,
        store: &S,
    ) -> CleanupStatus
    where
        C: RevokeTokenClient,
        S: RunLifecycleStore<Error = E>,
        E: fmt::Debug + fmt::Display,
    {
        match store.finish(
            &self.identity.run_id,
            self.identity.wrapper_pid,
            self.child_pid,
        ) {
            Ok(entry) => {
                let report = cleanup_marked_run_with_app(client, app, source_name, store, &entry);
                if report.is_complete() {
                    CleanupStatus::Complete
                } else {
                    CleanupStatus::Incomplete
                }
            }
            Err(err) => {
                tracing::debug!(error = %err, "failed to transition running run to cleanup pending on finish");
                CleanupStatus::Incomplete
            }
        }
    }
}

/// Renders a command line suitable for status display, escaping spaces and control characters.
pub fn render_command_line(command: &[OsString]) -> String {
    command
        .iter()
        .map(|part| {
            let part = part.to_string_lossy();
            let escaped = part
                .chars()
                .flat_map(char::escape_default)
                .collect::<String>();
            if part.is_empty() || part.chars().any(char::is_whitespace) {
                format!(r#""{escaped}""#)
            } else {
                escaped
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn generate_run_id<E>() -> Result<String, TokenError<E>> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random)?;
    let mut encoded = String::with_capacity(64);
    for byte in random {
        let _ = write!(encoded, "{byte:02x}");
    }
    Ok(encoded)
}

/// Executes the full foreground run workflow using current system time.
pub fn execute_run<C, S, Sp, Sf, E, P>(
    client: &C,
    store: &S,
    spawner: &Sp,
    signals: &Sf,
    request: &RunRequest<'_>,
) -> Result<Execution, ExecuteError<E, P>>
where
    C: ScopedTokenClient + RevokeTokenClient,
    S: ReadCredentials<Error = E>
        + WriteCredentials<Error = E>
        + IssuanceGuardStore<Error = E>
        + PendingRunStore<Error = E>
        + RunLifecycleStore<Error = E>,
    Sp: SpawnProcess<Error = P>,
    Sf: SignalForwarding<Error = P>,
    E: std::error::Error + 'static,
    P: std::error::Error + 'static,
{
    execute_run_with_clock(
        client,
        store,
        spawner,
        signals,
        request,
        OffsetDateTime::now_utc,
    )
}

/// Executes the foreground run workflow with an injected clock for deterministic testing.
pub fn execute_run_with_clock<C, S, Sp, Sf, E, P, N>(
    client: &C,
    store: &S,
    spawner: &Sp,
    signals: &Sf,
    request: &RunRequest<'_>,
    mut now: N,
) -> Result<Execution, ExecuteError<E, P>>
where
    C: ScopedTokenClient + RevokeTokenClient,
    S: ReadCredentials<Error = E>
        + WriteCredentials<Error = E>
        + IssuanceGuardStore<Error = E>
        + PendingRunStore<Error = E>
        + RunLifecycleStore<Error = E>,
    Sp: SpawnProcess<Error = P>,
    Sf: SignalForwarding<Error = P>,
    E: std::error::Error + 'static,
    P: std::error::Error + 'static,
    N: FnMut() -> OffsetDateTime,
{
    if request.command.is_empty() {
        return Err(ExecuteError::InvalidCommand);
    }

    let run_id = generate_run_id().map_err(ExecuteError::Token)?;
    let fresh_req = FreshScopedTokenRequest {
        profile_name: request.profile_name,
        source_name: request.source_name,
        app: request.app,
        repository_selection: request.repositories,
        permissions: request.permissions,
    };
    let fresh =
        issue_fresh_scoped(client, store, &fresh_req, &mut now).map_err(ExecuteError::Token)?;

    let rendered_command = render_command_line(request.command);
    let candidate = RunRecord {
        run_id,
        state: RunState::Pending,
        wrapper_pid: request.wrapper_pid,
        child_pid: None,
        command: rendered_command,
        profile: fresh.profile,
        source_profile: fresh.source_profile,
        source_authority_fingerprint: fresh.source_authority_fingerprint,
        github_user: fresh.github_user,
        repo_scope: fresh.repo_scope,
        expires_at: fresh.expires_at,
        access_token: fresh.access_token,
    };

    let pending = commit_pending_run(
        client,
        store,
        request,
        candidate,
        fresh.issuance_guard,
        &fresh.expected_base_generation,
    )?;

    run_child(client, store, spawner, signals, request, pending)
}

fn commit_pending_run<C, S, E, P>(
    client: &C,
    store: &S,
    request: &RunRequest<'_>,
    candidate: RunRecord,
    issuance_guard: crate::credential::store::IssuanceGuard,
    expected_base_generation: &str,
) -> Result<PendingRun, ExecuteError<E, P>>
where
    C: RevokeTokenClient,
    S: PendingRunStore<Error = E>,
    E: std::error::Error + 'static,
{
    let source_guard = SourceGuard {
        source_profile: &candidate.source_profile,
        expected_generation: expected_base_generation,
    };
    let outcome = match store.commit_pending(&candidate, issuance_guard, &source_guard) {
        Ok(outcome) => outcome,
        Err(storage_error) => {
            tracing::debug!(
                profile = request.profile_name,
                error = %storage_error,
                "failed to persist pending run recovery entry; revoking candidate"
            );
            return Err(ExecuteError::Token(revoke_with_context(
                client,
                &request.app.as_registration(),
                &candidate.access_token,
                TokenError::Storage(storage_error),
            )));
        }
    };

    match outcome {
        PendingRunOutcome::Saved => {
            tracing::debug!(
                profile = request.profile_name,
                run_id = candidate.run_id,
                "persisted pending run recovery entry"
            );
            Ok(PendingRun {
                identity: RunIdentity {
                    run_id: candidate.run_id,
                    wrapper_pid: candidate.wrapper_pid,
                },
                access_token: candidate.access_token,
            })
        }
        PendingRunOutcome::EpochChanged => {
            tracing::debug!(
                profile = request.profile_name,
                run_id = candidate.run_id,
                "cache epoch changed during run issuance; revoking candidate"
            );
            Err(ExecuteError::Token(revoke_with_context(
                client,
                &request.app.as_registration(),
                &candidate.access_token,
                TokenError::EpochChanged(request.profile_name.to_owned()),
            )))
        }
        PendingRunOutcome::BaseGenerationChanged => {
            tracing::debug!(
                profile = request.profile_name,
                run_id = candidate.run_id,
                "source base generation changed during run issuance; revoking candidate"
            );
            Err(ExecuteError::Token(revoke_with_context(
                client,
                &request.app.as_registration(),
                &candidate.access_token,
                TokenError::BaseGenerationChanged(request.profile_name.to_owned()),
            )))
        }
    }
}

fn run_child<C, S, Sp, Sf, E, P>(
    client: &C,
    store: &S,
    spawner: &Sp,
    signals: &Sf,
    request: &RunRequest<'_>,
    pending: PendingRun,
) -> Result<Execution, ExecuteError<E, P>>
where
    C: RevokeTokenClient,
    S: RunLifecycleStore<Error = E>,
    Sp: SpawnProcess<Error = P>,
    Sf: SignalForwarding<Error = P>,
    E: std::error::Error + 'static,
    P: std::error::Error + 'static,
{
    let prepared_signals = match signals.prepare() {
        Ok(prep) => prep,
        Err(source) => {
            let cleanup = pending.abort(client, &request.app, request.source_name, store, None);
            return Err(ExecuteError::PrepareSignals { source, cleanup });
        }
    };

    let spawn_request = SpawnRequest {
        command: request.command,
        token: pending.access_token(),
    };
    let mut child = match spawner.spawn(&spawn_request) {
        Ok(child) => child,
        Err(source) => {
            let cleanup = pending.abort(client, &request.app, request.source_name, store, None);
            return Err(ExecuteError::Spawn { source, cleanup });
        }
    };
    let child_pid = child.pid();

    let active_signals = match prepared_signals.start(child_pid) {
        Ok(active) => active,
        Err(source) => {
            child.terminate_and_wait();
            let cleanup = pending.abort(
                client,
                &request.app,
                request.source_name,
                store,
                Some(child_pid),
            );
            return Err(ExecuteError::StartForwarding { source, cleanup });
        }
    };

    let active_run = match pending.activate(store, child_pid) {
        Ok(active) => active,
        Err((source, pending)) => {
            active_signals.stop();
            child.terminate_and_wait();
            let cleanup = pending.abort(
                client,
                &request.app,
                request.source_name,
                store,
                Some(child_pid),
            );
            return Err(ExecuteError::Activation { source, cleanup });
        }
    };

    let exit_code = match child.wait() {
        Ok(exit) => exit,
        Err(err) => {
            tracing::warn!("failed to wait for run child: {err}");
            ProcessExit::new(1)
        }
    };

    active_signals.stop();
    let cleanup = active_run.finish(client, &request.app, request.source_name, store);

    Ok(Execution { exit_code, cleanup })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::store::{
        CommitBaseOutcome, CommitScopedOutcome, DeleteBaseOutcome, IssuanceGuard, ReplaceOutcome,
    };
    use crate::credential::{BaseCredential, ScopedCredential, TokenExpiry, authority_fingerprint};
    use crate::profile::AppAuthority;
    use crate::token::{IssuedScopedToken, RemoteError, ScopedTokenRequest};
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use time::Duration;

    #[derive(Debug)]
    struct MockError(&'static str);

    impl fmt::Display for MockError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for MockError {}

    #[derive(Clone, Default)]
    struct ExecutionTrace {
        events: Rc<RefCell<Vec<&'static str>>>,
    }

    impl ExecutionTrace {
        fn new() -> Self {
            Self::default()
        }

        fn record(&self, event: &'static str) {
            self.events.borrow_mut().push(event);
        }

        fn events(&self) -> Vec<&'static str> {
            self.events.borrow().clone()
        }
    }

    struct FakeWorkflowClient {
        trace: ExecutionTrace,
        delete_calls: RefCell<Vec<String>>,
        delete_fail: bool,
    }

    impl FakeWorkflowClient {
        fn new(trace: ExecutionTrace) -> Self {
            Self {
                trace,
                delete_calls: RefCell::new(Vec::new()),
                delete_fail: false,
            }
        }

        fn with_delete_fail(trace: ExecutionTrace) -> Self {
            Self {
                trace,
                delete_calls: RefCell::new(Vec::new()),
                delete_fail: true,
            }
        }
    }

    impl ScopedTokenClient for FakeWorkflowClient {
        fn create_scoped_token(
            &self,
            _request: &ScopedTokenRequest<'_>,
        ) -> Result<IssuedScopedToken, RemoteError> {
            self.trace.record("create_scoped_token");
            Ok(IssuedScopedToken {
                access_token: AccessToken::from("ghu_issued_run_tok_999"),
                expires_at: Some(
                    (OffsetDateTime::now_utc() + Duration::hours(1))
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap(),
                ),
            })
        }
    }

    impl RevokeTokenClient for FakeWorkflowClient {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            access_token: &str,
        ) -> Result<(), RemoteError> {
            self.trace.record("delete_token");
            self.delete_calls
                .borrow_mut()
                .push(access_token.to_string());
            if self.delete_fail {
                Err(RemoteError::Http {
                    status: 500,
                    message: "server error".into(),
                })
            } else {
                Ok(())
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum InjectedCommitOutcome {
        Saved,
        EpochChanged,
        BaseGenerationChanged,
        StorageError,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum InjectedStoreFailure {
        Activate,
        Finish,
        Delete,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum AbortObservation {
        NotAborted,
        WithoutChild,
        WithChild(u32),
    }

    struct FakeWorkflowStore {
        trace: ExecutionTrace,
        guard_counter: AtomicU64,
        pending_committed: Arc<AtomicBool>,
        injected_commit: InjectedCommitOutcome,
        injected_failure: Option<InjectedStoreFailure>,
        aborted_observation: RefCell<AbortObservation>,
    }

    impl FakeWorkflowStore {
        fn new(trace: ExecutionTrace) -> Self {
            Self {
                trace,
                guard_counter: AtomicU64::new(1),
                pending_committed: Arc::new(AtomicBool::new(false)),
                injected_commit: InjectedCommitOutcome::Saved,
                injected_failure: None,
                aborted_observation: RefCell::new(AbortObservation::NotAborted),
            }
        }
    }

    impl ReadCredentials for FakeWorkflowStore {
        type Error = MockError;

        fn read_base(&self, profile: &str) -> Result<Option<BaseCredential>, Self::Error> {
            self.trace.record("read_base");
            if profile == "developer" {
                Ok(Some(BaseCredential {
                    profile: "developer".into(),
                    authority_fingerprint: authority_fingerprint("client-1", "acme"),
                    github_user: "octocat".into(),
                    expires_at: TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(2)),
                    access_token: AccessToken::from("base-tok"),
                }))
            } else {
                Ok(None)
            }
        }

        fn read_scoped(
            &self,
            _profile: &str,
            _scope: &str,
        ) -> Result<Option<ScopedCredential>, Self::Error> {
            Ok(None)
        }
    }

    impl IssuanceGuardStore for FakeWorkflowStore {
        type Error = MockError;

        fn issuance_guard(&self) -> Result<IssuanceGuard, Self::Error> {
            self.trace.record("issuance_guard");
            let id = self.guard_counter.fetch_add(1, Ordering::SeqCst);
            Ok(IssuanceGuard::new(id))
        }
    }

    impl WriteCredentials for FakeWorkflowStore {
        type Error = MockError;

        fn commit_base(
            &self,
            _candidate: &BaseCredential,
            _guard: IssuanceGuard,
        ) -> Result<CommitBaseOutcome, Self::Error> {
            unimplemented!()
        }

        fn commit_scoped(
            &self,
            _candidate: &ScopedCredential,
            _guard: IssuanceGuard,
            _source: &SourceGuard<'_>,
        ) -> Result<CommitScopedOutcome, Self::Error> {
            unimplemented!()
        }

        fn renew_scoped(
            &self,
            _expected: &ScopedCredential,
            _candidate: &ScopedCredential,
            _guard: IssuanceGuard,
            _source: &SourceGuard<'_>,
            _now: OffsetDateTime,
        ) -> Result<ReplaceOutcome<ScopedCredential>, Self::Error> {
            unimplemented!()
        }

        fn delete_base_if_generation(
            &self,
            _profile: &str,
            _expected_generation: &str,
        ) -> Result<DeleteBaseOutcome, Self::Error> {
            unimplemented!()
        }
    }

    impl PendingRunStore for FakeWorkflowStore {
        type Error = MockError;

        fn commit_pending(
            &self,
            _candidate: &RunRecord,
            _guard: IssuanceGuard,
            _source: &SourceGuard<'_>,
        ) -> Result<PendingRunOutcome, Self::Error> {
            self.trace.record("commit_pending");
            match self.injected_commit {
                InjectedCommitOutcome::Saved => {
                    self.pending_committed.store(true, Ordering::SeqCst);
                    Ok(PendingRunOutcome::Saved)
                }
                InjectedCommitOutcome::EpochChanged => Ok(PendingRunOutcome::EpochChanged),
                InjectedCommitOutcome::BaseGenerationChanged => {
                    Ok(PendingRunOutcome::BaseGenerationChanged)
                }
                InjectedCommitOutcome::StorageError => {
                    Err(MockError("commit pending storage error"))
                }
            }
        }
    }

    impl RunLifecycleStore for FakeWorkflowStore {
        type Error = MockError;

        fn activate(
            &self,
            run_id: &str,
            wrapper_pid: u32,
            child_pid: u32,
        ) -> Result<RunRecord, Self::Error> {
            self.trace.record("activate");
            if self.injected_failure == Some(InjectedStoreFailure::Activate) {
                return Err(MockError("activate failed"));
            }
            Ok(RunRecord {
                run_id: run_id.into(),
                state: RunState::Running,
                wrapper_pid,
                child_pid: Some(child_pid),
                command: "cmd".into(),
                profile: "reader".into(),
                source_profile: "developer".into(),
                source_authority_fingerprint: authority_fingerprint("client-1", "acme"),
                github_user: "octocat".into(),
                repo_scope: "all".into(),
                expires_at: TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(1)),
                access_token: AccessToken::from("ghu_issued_run_tok_999"),
            })
        }

        fn abort(
            &self,
            run_id: &str,
            wrapper_pid: u32,
            child_pid: Option<u32>,
        ) -> Result<RunRecord, Self::Error> {
            self.trace.record("abort");
            *self.aborted_observation.borrow_mut() =
                child_pid.map_or(AbortObservation::WithoutChild, AbortObservation::WithChild);
            Ok(RunRecord {
                run_id: run_id.into(),
                state: RunState::CleanupPending,
                wrapper_pid,
                child_pid,
                command: "cmd".into(),
                profile: "reader".into(),
                source_profile: "developer".into(),
                source_authority_fingerprint: authority_fingerprint("client-1", "acme"),
                github_user: "octocat".into(),
                repo_scope: "all".into(),
                expires_at: TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(1)),
                access_token: AccessToken::from("ghu_issued_run_tok_999"),
            })
        }

        fn finish(
            &self,
            run_id: &str,
            wrapper_pid: u32,
            child_pid: u32,
        ) -> Result<RunRecord, Self::Error> {
            self.trace.record("finish");
            if self.injected_failure == Some(InjectedStoreFailure::Finish) {
                return Err(MockError("finish failed"));
            }
            Ok(RunRecord {
                run_id: run_id.into(),
                state: RunState::CleanupPending,
                wrapper_pid,
                child_pid: Some(child_pid),
                command: "cmd".into(),
                profile: "reader".into(),
                source_profile: "developer".into(),
                source_authority_fingerprint: authority_fingerprint("client-1", "acme"),
                github_user: "octocat".into(),
                repo_scope: "all".into(),
                expires_at: TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(1)),
                access_token: AccessToken::from("ghu_issued_run_tok_999"),
            })
        }

        fn claim_abandoned(&self, _expected: &RunRecord) -> Result<RunRecord, Self::Error> {
            unimplemented!()
        }

        fn delete_cleanup_pending(&self, _expected: &RunRecord) -> Result<bool, Self::Error> {
            self.trace.record("delete_cleanup_pending");
            if self.injected_failure == Some(InjectedStoreFailure::Delete) {
                return Err(MockError("delete failed"));
            }
            Ok(true)
        }
    }

    struct FakeChild {
        trace: ExecutionTrace,
        exit_code: Option<i32>,
        fail_wait: bool,
    }

    impl ChildProcess for FakeChild {
        type Error = MockError;

        fn pid(&self) -> u32 {
            4321
        }

        fn wait(&mut self) -> Result<ProcessExit, Self::Error> {
            self.trace.record("child_wait");
            if self.fail_wait {
                Err(MockError("wait failed"))
            } else {
                Ok(ProcessExit::new(self.exit_code.unwrap_or(0)))
            }
        }

        fn terminate_and_wait(&mut self) {
            self.trace.record("terminate_and_wait");
        }
    }

    struct FakeSpawner {
        trace: ExecutionTrace,
        fail_spawn: bool,
        child_exit: i32,
        fail_wait: bool,
        assert_store_committed: Option<Arc<AtomicBool>>,
    }

    impl FakeSpawner {
        fn new(trace: ExecutionTrace) -> Self {
            Self {
                trace,
                fail_spawn: false,
                child_exit: 0,
                fail_wait: false,
                assert_store_committed: None,
            }
        }
    }

    impl SpawnProcess for FakeSpawner {
        type Child = FakeChild;
        type Error = MockError;

        fn spawn(&self, request: &SpawnRequest<'_>) -> Result<Self::Child, Self::Error> {
            self.trace.record("spawn");
            if let Some(ref committed) = self.assert_store_committed {
                assert!(
                    committed.load(Ordering::SeqCst),
                    "store must commit pending before spawn!"
                );
            }
            assert_eq!(request.token, "ghu_issued_run_tok_999");
            if self.fail_spawn {
                Err(MockError("spawn failed"))
            } else {
                Ok(FakeChild {
                    trace: self.trace.clone(),
                    exit_code: Some(self.child_exit),
                    fail_wait: self.fail_wait,
                })
            }
        }
    }

    struct FakeActiveSignals {
        trace: ExecutionTrace,
    }

    impl ActiveSignals for FakeActiveSignals {
        fn stop(self) {
            self.trace.record("stop_signals");
        }
    }

    struct FakePreparedSignals {
        trace: ExecutionTrace,
        fail_start: bool,
    }

    impl PreparedSignals for FakePreparedSignals {
        type Active = FakeActiveSignals;
        type Error = MockError;

        fn start(self, child_pid: u32) -> Result<Self::Active, Self::Error> {
            self.trace.record("start_signals");
            assert_eq!(child_pid, 4321);
            if self.fail_start {
                Err(MockError("start forwarding failed"))
            } else {
                Ok(FakeActiveSignals { trace: self.trace })
            }
        }
    }

    struct FakeSignalForwarding {
        trace: ExecutionTrace,
        fail_prepare: bool,
        fail_start: bool,
    }

    impl FakeSignalForwarding {
        fn new(trace: ExecutionTrace) -> Self {
            Self {
                trace,
                fail_prepare: false,
                fail_start: false,
            }
        }
    }

    impl SignalForwarding for FakeSignalForwarding {
        type Prepared = FakePreparedSignals;
        type Error = MockError;

        fn prepare(&self) -> Result<Self::Prepared, Self::Error> {
            self.trace.record("prepare_signals");
            if self.fail_prepare {
                Err(MockError("prepare signals failed"))
            } else {
                Ok(FakePreparedSignals {
                    trace: self.trace.clone(),
                    fail_start: self.fail_start,
                })
            }
        }
    }

    fn sample_request<'a>(
        command: &'a [OsString],
        repos: &'a RepositorySelection,
        perms: &'a BTreeMap<String, PermissionLevel>,
    ) -> RunRequest<'a> {
        RunRequest {
            profile_name: "reader",
            source_name: "developer",
            app: AppCredentials {
                authority: AppAuthority {
                    account: "acme",
                    client_id: "client-1",
                },
                client_secret: "secret-1",
            },
            permissions: perms,
            repositories: repos,
            wrapper_pid: 1000,
            command,
        }
    }

    fn sample_repos() -> RepositorySelection {
        RepositorySelection::resolve(
            &[],
            &crate::profile::RepoScope::All,
            "acme",
            || unreachable!(),
        )
        .unwrap()
    }

    #[test]
    fn test_run_workflow_happy_path_order_and_cleanup() {
        let trace = ExecutionTrace::new();
        let client = FakeWorkflowClient::new(trace.clone());
        let store = FakeWorkflowStore::new(trace.clone());
        let spawner = FakeSpawner::new(trace.clone());
        let signals = FakeSignalForwarding::new(trace.clone());
        let cmd = [OsString::from("echo"), OsString::from("hi")];
        let repos = sample_repos();
        let perms = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);
        let req = sample_request(&cmd, &repos, &perms);

        let execution = execute_run(&client, &store, &spawner, &signals, &req).unwrap();
        assert_eq!(execution.exit_code.code(), 0);
        assert_eq!(execution.cleanup, CleanupStatus::Complete);

        // Sequence: read_base -> issuance_guard -> create_scoped_token -> commit_pending -> prepare_signals -> spawn -> start_signals -> activate -> child_wait -> stop_signals -> finish -> delete_token -> delete_cleanup_pending
        assert_eq!(
            trace.events(),
            vec![
                "read_base",
                "issuance_guard",
                "create_scoped_token",
                "commit_pending",
                "prepare_signals",
                "spawn",
                "start_signals",
                "activate",
                "child_wait",
                "stop_signals",
                "finish",
                "delete_token",
                "delete_cleanup_pending",
            ]
        );
        assert_eq!(
            *client.delete_calls.borrow(),
            vec!["ghu_issued_run_tok_999"]
        );
    }

    #[test]
    fn test_pending_durability_store_commits_before_spawn() {
        let trace = ExecutionTrace::new();
        let client = FakeWorkflowClient::new(trace.clone());
        let store = FakeWorkflowStore::new(trace.clone());
        let mut spawner = FakeSpawner::new(trace.clone());
        spawner.assert_store_committed = Some(Arc::clone(&store.pending_committed));

        let cmd = [OsString::from("echo"), OsString::from("hi")];
        let repos = sample_repos();
        let perms = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);
        let req = sample_request(&cmd, &repos, &perms);

        let signals = FakeSignalForwarding::new(trace);
        assert!(execute_run(&client, &store, &spawner, &signals, &req).is_ok());
        assert!(store.pending_committed.load(Ordering::SeqCst));
    }

    #[test]
    fn test_prepare_signals_failure_aborts_without_child_pid() {
        let trace = ExecutionTrace::new();
        let client = FakeWorkflowClient::new(trace.clone());
        let store = FakeWorkflowStore::new(trace.clone());
        let spawner = FakeSpawner::new(trace.clone());
        let mut signals = FakeSignalForwarding::new(trace.clone());
        signals.fail_prepare = true;

        let cmd = [OsString::from("echo"), OsString::from("hi")];
        let repos = sample_repos();
        let perms = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);
        let req = sample_request(&cmd, &repos, &perms);

        let err = execute_run(&client, &store, &spawner, &signals, &req).unwrap_err();
        assert!(matches!(err, ExecuteError::PrepareSignals { .. }));
        assert_eq!(err.cleanup_status(), Some(CleanupStatus::Complete));

        assert_eq!(
            trace.events(),
            vec![
                "read_base",
                "issuance_guard",
                "create_scoped_token",
                "commit_pending",
                "prepare_signals",
                "abort",
                "delete_token",
                "delete_cleanup_pending",
            ]
        );
        assert_eq!(
            *store.aborted_observation.borrow(),
            AbortObservation::WithoutChild
        );
    }

    #[test]
    fn test_spawn_failure_aborts_without_child_pid() {
        let trace = ExecutionTrace::new();
        let client = FakeWorkflowClient::new(trace.clone());
        let store = FakeWorkflowStore::new(trace.clone());
        let mut spawner = FakeSpawner::new(trace.clone());
        spawner.fail_spawn = true;
        let signals = FakeSignalForwarding::new(trace.clone());

        let cmd = [OsString::from("echo"), OsString::from("hi")];
        let repos = sample_repos();
        let perms = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);
        let req = sample_request(&cmd, &repos, &perms);

        let err = execute_run(&client, &store, &spawner, &signals, &req).unwrap_err();
        assert!(matches!(err, ExecuteError::Spawn { .. }));
        assert_eq!(err.cleanup_status(), Some(CleanupStatus::Complete));

        assert_eq!(
            trace.events(),
            vec![
                "read_base",
                "issuance_guard",
                "create_scoped_token",
                "commit_pending",
                "prepare_signals",
                "spawn",
                "abort",
                "delete_token",
                "delete_cleanup_pending",
            ]
        );
        assert_eq!(
            *store.aborted_observation.borrow(),
            AbortObservation::WithoutChild
        );
    }

    #[test]
    fn test_start_forwarding_failure_terminates_and_aborts_with_child_pid() {
        let trace = ExecutionTrace::new();
        let client = FakeWorkflowClient::new(trace.clone());
        let store = FakeWorkflowStore::new(trace.clone());
        let spawner = FakeSpawner::new(trace.clone());
        let mut signals = FakeSignalForwarding::new(trace.clone());
        signals.fail_start = true;

        let cmd = [OsString::from("echo"), OsString::from("hi")];
        let repos = sample_repos();
        let perms = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);
        let req = sample_request(&cmd, &repos, &perms);

        let err = execute_run(&client, &store, &spawner, &signals, &req).unwrap_err();
        assert!(matches!(err, ExecuteError::StartForwarding { .. }));
        assert_eq!(err.cleanup_status(), Some(CleanupStatus::Complete));

        // Note: terminate_and_wait MUST be called on the child before abort!
        assert_eq!(
            trace.events(),
            vec![
                "read_base",
                "issuance_guard",
                "create_scoped_token",
                "commit_pending",
                "prepare_signals",
                "spawn",
                "start_signals",
                "terminate_and_wait",
                "abort",
                "delete_token",
                "delete_cleanup_pending",
            ]
        );
        assert_eq!(
            *store.aborted_observation.borrow(),
            AbortObservation::WithChild(4321)
        );
    }

    #[test]
    fn test_activation_failure_terminates_and_aborts_with_child_pid() {
        let trace = ExecutionTrace::new();
        let client = FakeWorkflowClient::new(trace.clone());
        let mut store = FakeWorkflowStore::new(trace.clone());
        store.injected_failure = Some(InjectedStoreFailure::Activate);
        let spawner = FakeSpawner::new(trace.clone());
        let signals = FakeSignalForwarding::new(trace.clone());

        let cmd = [OsString::from("echo"), OsString::from("hi")];
        let repos = sample_repos();
        let perms = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);
        let req = sample_request(&cmd, &repos, &perms);

        let err = execute_run(&client, &store, &spawner, &signals, &req).unwrap_err();
        assert!(matches!(err, ExecuteError::Activation { .. }));
        assert_eq!(err.cleanup_status(), Some(CleanupStatus::Complete));

        // Note: stop_signals, then terminate_and_wait on child, then abort!
        assert_eq!(
            trace.events(),
            vec![
                "read_base",
                "issuance_guard",
                "create_scoped_token",
                "commit_pending",
                "prepare_signals",
                "spawn",
                "start_signals",
                "activate",
                "stop_signals",
                "terminate_and_wait",
                "abort",
                "delete_token",
                "delete_cleanup_pending",
            ]
        );
        assert_eq!(
            *store.aborted_observation.borrow(),
            AbortObservation::WithChild(4321)
        );
    }

    #[test]
    fn test_child_wait_failure_yields_exit_code_1_and_runs_cleanup() {
        let trace = ExecutionTrace::new();
        let client = FakeWorkflowClient::new(trace.clone());
        let store = FakeWorkflowStore::new(trace.clone());
        let mut spawner = FakeSpawner::new(trace.clone());
        spawner.fail_wait = true;
        let signals = FakeSignalForwarding::new(trace.clone());

        let cmd = [OsString::from("echo"), OsString::from("hi")];
        let repos = sample_repos();
        let perms = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);
        let req = sample_request(&cmd, &repos, &perms);

        let execution = execute_run(&client, &store, &spawner, &signals, &req).unwrap();
        // Child wait failure defaults to exit code 1
        assert_eq!(execution.exit_code.code(), 1);
        assert_eq!(execution.cleanup, CleanupStatus::Complete);
        assert_eq!(
            trace.events(),
            vec![
                "read_base",
                "issuance_guard",
                "create_scoped_token",
                "commit_pending",
                "prepare_signals",
                "spawn",
                "start_signals",
                "activate",
                "child_wait",
                "stop_signals",
                "finish",
                "delete_token",
                "delete_cleanup_pending",
            ]
        );
    }

    #[test]
    fn test_child_exit_preserved_when_cleanup_fails() {
        for child_code in [0, 42, 143] {
            let trace = ExecutionTrace::new();
            let client = FakeWorkflowClient::with_delete_fail(trace.clone());
            let store = FakeWorkflowStore::new(trace.clone());
            let mut spawner = FakeSpawner::new(trace.clone());
            spawner.child_exit = child_code;
            let signals = FakeSignalForwarding::new(trace.clone());

            let cmd = [OsString::from("exit"), OsString::from("code")];
            let repos = sample_repos();
            let perms = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);
            let req = sample_request(&cmd, &repos, &perms);

            let execution = execute_run(&client, &store, &spawner, &signals, &req).unwrap();
            // Child exit code is preserved!
            assert_eq!(execution.exit_code.code(), child_code);
            // Cleanup is incomplete
            assert_eq!(execution.cleanup, CleanupStatus::Incomplete);
        }
    }

    #[test]
    fn test_commit_pending_storage_error_revokes_candidate_without_spawning() {
        let trace = ExecutionTrace::new();
        let client = FakeWorkflowClient::new(trace.clone());
        let mut store = FakeWorkflowStore::new(trace.clone());
        store.injected_commit = InjectedCommitOutcome::StorageError;
        let spawner = FakeSpawner::new(trace.clone());
        let signals = FakeSignalForwarding::new(trace.clone());

        let cmd = [OsString::from("echo"), OsString::from("hi")];
        let repos = sample_repos();
        let perms = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);
        let req = sample_request(&cmd, &repos, &perms);

        let err = execute_run(&client, &store, &spawner, &signals, &req).unwrap_err();
        assert!(matches!(err, ExecuteError::Token(TokenError::Storage(_))));
        assert_eq!(err.cleanup_status(), None);

        assert_eq!(
            trace.events(),
            vec![
                "read_base",
                "issuance_guard",
                "create_scoped_token",
                "commit_pending",
                "delete_token",
            ]
        );
        assert_eq!(
            *client.delete_calls.borrow(),
            vec!["ghu_issued_run_tok_999"]
        );
    }

    #[test]
    fn test_commit_pending_epoch_changed_revokes_candidate_without_spawning() {
        let trace = ExecutionTrace::new();
        let client = FakeWorkflowClient::new(trace.clone());
        let mut store = FakeWorkflowStore::new(trace.clone());
        store.injected_commit = InjectedCommitOutcome::EpochChanged;
        let spawner = FakeSpawner::new(trace.clone());
        let signals = FakeSignalForwarding::new(trace.clone());

        let cmd = [OsString::from("echo"), OsString::from("hi")];
        let repos = sample_repos();
        let perms = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);
        let req = sample_request(&cmd, &repos, &perms);

        let err = execute_run(&client, &store, &spawner, &signals, &req).unwrap_err();
        assert!(matches!(
            err,
            ExecuteError::Token(TokenError::EpochChanged(ref p)) if p == "reader"
        ));
        assert_eq!(err.cleanup_status(), None);

        assert_eq!(
            trace.events(),
            vec![
                "read_base",
                "issuance_guard",
                "create_scoped_token",
                "commit_pending",
                "delete_token",
            ]
        );
        assert_eq!(
            *client.delete_calls.borrow(),
            vec!["ghu_issued_run_tok_999"]
        );
    }

    #[test]
    fn run_ids_are_unique_random_and_domain_separated() {
        use crate::cache::{compute_cache_key, compute_run_cache_key};
        let first = generate_run_id::<crate::cache::CacheError>().unwrap();
        let second = generate_run_id::<crate::cache::CacheError>().unwrap();
        assert_eq!(first.len(), 64, "run ID must be 64 hex characters");
        assert_ne!(first, second, "run IDs must be unique across calls");
        assert_ne!(
            compute_run_cache_key(&first),
            compute_cache_key("run", &first),
            "run cache key must be domain-separated from the generic cache key scheme"
        );
    }

    #[test]
    fn rendered_command_line_cannot_inject_status_lines() {
        let command = [
            OsString::from("printf"),
            OsString::from("first\n    Lifetime: Fake"),
        ];
        assert_eq!(
            render_command_line(&command),
            r#"printf "first\n    Lifetime: Fake""#,
            "newlines in arguments must be escaped to prevent status-line injection"
        );
    }

    #[test]
    fn test_commit_pending_base_generation_changed_revokes_candidate_without_spawning() {
        let trace = ExecutionTrace::new();
        let client = FakeWorkflowClient::new(trace.clone());
        let mut store = FakeWorkflowStore::new(trace.clone());
        store.injected_commit = InjectedCommitOutcome::BaseGenerationChanged;
        let spawner = FakeSpawner::new(trace.clone());
        let signals = FakeSignalForwarding::new(trace.clone());

        let cmd = [OsString::from("echo"), OsString::from("hi")];
        let repos = sample_repos();
        let perms = BTreeMap::from([("contents".to_string(), PermissionLevel::Read)]);
        let req = sample_request(&cmd, &repos, &perms);

        let err = execute_run(&client, &store, &spawner, &signals, &req).unwrap_err();
        assert!(matches!(
            err,
            ExecuteError::Token(TokenError::BaseGenerationChanged(ref p)) if p == "reader"
        ));
        assert_eq!(err.cleanup_status(), None);

        assert_eq!(
            trace.events(),
            vec![
                "read_base",
                "issuance_guard",
                "create_scoped_token",
                "commit_pending",
                "delete_token",
            ]
        );
        assert_eq!(
            *client.delete_calls.borrow(),
            vec!["ghu_issued_run_tok_999"]
        );
    }
}
