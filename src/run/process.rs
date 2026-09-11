use std::ffi::OsString;
use std::fmt;

/// Terminal exit status of a child process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessExit(i32);

impl ProcessExit {
    #[inline]
    pub const fn new(code: i32) -> Self {
        Self(code)
    }

    #[inline]
    pub const fn code(self) -> i32 {
        self.0
    }

    #[cfg(unix)]
    pub fn from_status(status: std::process::ExitStatus) -> Self {
        use std::os::unix::process::ExitStatusExt;
        let code = match (status.code(), status.signal()) {
            (Some(code), _) => code,
            (None, Some(signal)) => 128 + signal,
            (None, None) => 1,
        };
        Self(code)
    }

    #[cfg(not(unix))]
    pub fn from_status(status: std::process::ExitStatus) -> Self {
        Self(status.code().unwrap_or(1))
    }
}

/// Token and command arguments for spawning a process.
pub struct SpawnRequest<'a> {
    pub command: &'a [OsString],
    pub token: &'a str,
}

impl fmt::Debug for SpawnRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpawnRequest")
            .field("command_len", &self.command.len())
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Spawns a direct child process from arguments and token environment.
pub trait SpawnProcess {
    type Child: ChildProcess;
    type Error: std::error::Error + 'static;

    fn spawn(&self, request: &SpawnRequest<'_>) -> Result<Self::Child, Self::Error>;
}

/// Direct child process handle.
pub trait ChildProcess {
    type Error: std::error::Error + 'static;

    fn pid(&self) -> u32;
    fn wait(&mut self) -> Result<ProcessExit, Self::Error>;
    fn terminate_and_wait(&mut self);
}

/// Prepares signal interception before spawning a child process.
pub trait SignalForwarding {
    type Prepared: PreparedSignals<Error = Self::Error>;
    type Error: std::error::Error + 'static;

    fn prepare(&self) -> Result<Self::Prepared, Self::Error>;
}

/// Prepared signal observation ready to start forwarding to a spawned child PID.
pub trait PreparedSignals {
    type Active: ActiveSignals;
    type Error: std::error::Error + 'static;

    fn start(self, child_pid: u32) -> Result<Self::Active, Self::Error>;
}

/// Active signal forwarding handle that can be stopped and joined.
pub trait ActiveSignals {
    fn stop(self);
}

/// Semantic result of checking whether a process is alive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LivenessOutcome {
    Dead,
    AliveOrUnknown,
}

/// Contract for checking process existence by PID without terminating it.
pub trait ProcessLiveness {
    fn check_liveness(&self, pid: u32) -> LivenessOutcome;
}

/// Production process adapter using standard library, `signal_hook`, and rustix.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsProcess;

/// Real child process handle wrapping `std::process::Child`.
pub struct LocalChild(std::process::Child);

impl ChildProcess for LocalChild {
    type Error = std::io::Error;

    fn pid(&self) -> u32 {
        self.0.id()
    }

    fn wait(&mut self) -> Result<ProcessExit, Self::Error> {
        let status = self.0.wait()?;
        Ok(ProcessExit::from_status(status))
    }

    fn terminate_and_wait(&mut self) {
        if let Err(error) = self.0.kill() {
            tracing::warn!("failed to terminate untracked run child: {error}");
        }
        if let Err(error) = self.0.wait() {
            tracing::warn!("failed to wait for untracked run child: {error}");
        }
    }
}

impl SpawnProcess for OsProcess {
    type Child = LocalChild;
    type Error = std::io::Error;

    fn spawn(&self, request: &SpawnRequest<'_>) -> Result<Self::Child, Self::Error> {
        if request.command.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "command must not be empty",
            ));
        }
        let mut command = std::process::Command::new(&request.command[0]);
        command
            .args(&request.command[1..])
            .env("GH_TOKEN", request.token)
            .env("GITHUB_TOKEN", request.token)
            .env_remove("GH_ENTERPRISE_TOKEN")
            .env_remove("GITHUB_ENTERPRISE_TOKEN");
        let child = command.spawn()?;
        Ok(LocalChild(child))
    }
}

#[cfg(unix)]
pub struct LocalPreparedSignals(signal_hook::iterator::Signals);

#[cfg(unix)]
pub struct LocalActiveSignals {
    handle: signal_hook::iterator::Handle,
    thread: std::thread::JoinHandle<()>,
}

#[cfg(unix)]
impl PreparedSignals for LocalPreparedSignals {
    type Active = LocalActiveSignals;
    type Error = std::io::Error;

    fn start(mut self, child_pid: u32) -> Result<Self::Active, Self::Error> {
        let handle = self.0.handle();
        let thread = std::thread::Builder::new()
            .name("ghst-signal-forwarder".to_owned())
            .spawn(move || {
                use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
                let Ok(raw_pid) = i32::try_from(child_pid) else {
                    return;
                };
                let Some(pid) = rustix::process::Pid::from_raw(raw_pid) else {
                    return;
                };
                for raw_signal in self.0.forever() {
                    let signal = match raw_signal {
                        SIGINT => rustix::process::Signal::INT,
                        SIGTERM => rustix::process::Signal::TERM,
                        SIGHUP => rustix::process::Signal::HUP,
                        SIGQUIT => rustix::process::Signal::QUIT,
                        _ => continue,
                    };
                    if let Err(error) = rustix::process::kill_process(pid, signal)
                        && error != rustix::io::Errno::SRCH
                    {
                        tracing::warn!("failed to forward signal to run child: {error}");
                    }
                }
            })?;
        Ok(LocalActiveSignals { handle, thread })
    }
}

#[cfg(unix)]
impl ActiveSignals for LocalActiveSignals {
    fn stop(self) {
        self.handle.close();
        if self.thread.join().is_err() {
            tracing::warn!("run signal-forwarding thread panicked");
        }
    }
}

#[cfg(not(unix))]
pub struct LocalPreparedSignals;

#[cfg(not(unix))]
pub struct LocalActiveSignals;

#[cfg(not(unix))]
impl PreparedSignals for LocalPreparedSignals {
    type Active = LocalActiveSignals;
    type Error = std::io::Error;

    fn start(self, _child_pid: u32) -> Result<Self::Active, Self::Error> {
        Ok(LocalActiveSignals)
    }
}

#[cfg(not(unix))]
impl ActiveSignals for LocalActiveSignals {
    fn stop(self) {}
}

impl SignalForwarding for OsProcess {
    type Prepared = LocalPreparedSignals;
    type Error = std::io::Error;

    #[cfg(unix)]
    fn prepare(&self) -> Result<Self::Prepared, Self::Error> {
        use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
        signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP, SIGQUIT])
            .map(LocalPreparedSignals)
    }

    #[cfg(not(unix))]
    fn prepare(&self) -> Result<Self::Prepared, Self::Error> {
        Ok(LocalPreparedSignals)
    }
}

impl ProcessLiveness for OsProcess {
    #[cfg(unix)]
    fn check_liveness(&self, pid: u32) -> LivenessOutcome {
        let Ok(raw) = i32::try_from(pid) else {
            return LivenessOutcome::AliveOrUnknown;
        };
        let Some(pid) = rustix::process::Pid::from_raw(raw) else {
            return LivenessOutcome::AliveOrUnknown;
        };
        match rustix::process::test_kill_process(pid) {
            Err(rustix::io::Errno::SRCH) => LivenessOutcome::Dead,
            _ => LivenessOutcome::AliveOrUnknown,
        }
    }

    #[cfg(not(unix))]
    fn check_liveness(&self, _pid: u32) -> LivenessOutcome {
        LivenessOutcome::AliveOrUnknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_request_debug_redacts_token() {
        let cmd = [OsString::from("echo"), OsString::from("hello")];
        let req = SpawnRequest {
            command: &cmd,
            token: "super-secret-token-12345",
        };
        let debug = format!("{req:?}");
        assert!(!debug.contains("super-secret-token-12345"));
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("command_len: 2"));
    }

    #[test]
    fn child_environment_is_replaced_and_arguments_are_preserved() {
        let cmd = [
            OsString::from("sh"),
            OsString::from("-c"),
            OsString::from(
                "test \"$GH_TOKEN\" = fresh && test \"$GITHUB_TOKEN\" = fresh && test -z \"$GH_ENTERPRISE_TOKEN\" && test -z \"$GITHUB_ENTERPRISE_TOKEN\" && test \"$1\" = 'a b'",
            ),
            OsString::from("sh"),
            OsString::from("a b"),
        ];
        let req = SpawnRequest {
            command: &cmd,
            token: "fresh",
        };
        let mut child = OsProcess.spawn(&req).unwrap();
        let exit = child.wait().unwrap();
        assert_eq!(exit.code(), 0);
    }

    #[test]
    fn child_exit_codes_and_signals_are_mapped() {
        let cmd = [
            OsString::from("sh"),
            OsString::from("-c"),
            OsString::from("exit 37"),
        ];
        let req = SpawnRequest {
            command: &cmd,
            token: "token",
        };
        let mut child = OsProcess.spawn(&req).unwrap();
        let exit = child.wait().unwrap();
        assert_eq!(exit.code(), 37);

        #[cfg(unix)]
        {
            let cmd_term = [
                OsString::from("sh"),
                OsString::from("-c"),
                OsString::from("kill -TERM $$"),
            ];
            let req_term = SpawnRequest {
                command: &cmd_term,
                token: "token",
            };
            let mut child_term = OsProcess.spawn(&req_term).unwrap();
            let exit_term = child_term.wait().unwrap();
            assert_eq!(exit_term.code(), 143);
        }
    }

    #[test]
    fn test_process_liveness_current_pid_is_alive() {
        let pid = std::process::id();
        let outcome = OsProcess.check_liveness(pid);
        assert_eq!(outcome, LivenessOutcome::AliveOrUnknown);
    }

    #[cfg(unix)]
    #[test]
    fn test_process_liveness_reaped_child_is_dead() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("failed to spawn child process");
        let pid = child.id();
        let _ = child.wait().expect("failed to wait on child process");
        let outcome = OsProcess.check_liveness(pid);
        assert_eq!(outcome, LivenessOutcome::Dead);
    }
}
