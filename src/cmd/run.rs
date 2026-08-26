use crate::cache::{mark_pending_run_for_cleanup, transition_run_to_running};
use crate::cmd::{CmdError, GhstCli, RunCmd, resolve_profile_name};
use crate::github::GitHubClient;
use crate::token::cleanup::{CleanupScope, ReleasedRun, cleanup, cleanup_marked_run};
use crate::token::run::{MintRunRequest, PendingRun};
use std::process::{Command, ExitStatus};
use time::OffsetDateTime;

pub enum RunOutcome {
    GhstError(CmdError),
    ChildExit(i32),
}

impl From<CmdError> for RunOutcome {
    fn from(error: CmdError) -> Self {
        Self::GhstError(error)
    }
}

pub fn run_run(args: &GhstCli, cmd: &RunCmd) -> RunOutcome {
    match execute(args, cmd) {
        Ok(code) => RunOutcome::ChildExit(code),
        Err(error) => RunOutcome::GhstError(error),
    }
}

fn execute(args: &GhstCli, cmd: &RunCmd) -> Result<i32, CmdError> {
    if cmd.command.is_empty() {
        return Err(CmdError::MissingRunCommand);
    }
    let config = crate::config::load(args.config.as_deref())?;
    let profile_name = resolve_profile_name(cmd.profile.as_deref(), &config)?;
    let cache_dir = crate::config::cache_dir()?;
    let client = GitHubClient::new();
    let wrapper_pid = std::process::id();
    let command_line = render_command_line(&cmd.command);
    tracing::debug!(
        profile = profile_name,
        requested_repositories = ?cmd.repo,
        wrapper_pid,
        "minting a fresh run token"
    );
    let pending = crate::token::run::mint(
        &client,
        &MintRunRequest {
            config: &config,
            cache_dir: &cache_dir,
            profile_name: &profile_name,
            repositories: &cmd.repo,
            wrapper_pid,
            command: &command_line,
        },
        crate::git::resolve_origin_repo,
    )?;
    #[cfg(unix)]
    let signals = match Forwarder::prepare() {
        Ok(signals) => signals,
        Err(error) => {
            cleanup_before_handoff(&client, &config, &cache_dir, &pending, None);
            return Err(CmdError::Io(error));
        }
    };

    tracing::debug!(executable = ?cmd.command[0], "spawning run child process");
    let mut child = match spawn_command(cmd, pending.access_token.as_ref()) {
        Ok(child) => child,
        Err(error) => {
            cleanup_before_handoff(&client, &config, &cache_dir, &pending, None);
            return Err(CmdError::Io(error));
        }
    };
    let child_pid = child.id();
    tracing::debug!(child_pid, "run child process spawned");

    #[cfg(unix)]
    let forwarder = match signals.start(child_pid) {
        Ok(forwarder) => forwarder,
        Err(error) => {
            terminate_and_wait(&mut child);
            cleanup_before_handoff(&client, &config, &cache_dir, &pending, Some(child_pid));
            return Err(CmdError::Io(error));
        }
    };

    if let Err(error) = transition_run_to_running(
        &cache_dir,
        &pending.cache_key,
        &pending.run_id,
        wrapper_pid,
        child_pid,
    ) {
        tracing::debug!(child_pid, error = %error, "failed to transition run recovery entry to running");
        #[cfg(unix)]
        forwarder.stop();
        terminate_and_wait(&mut child);
        cleanup_before_handoff(&client, &config, &cache_dir, &pending, Some(child_pid));
        return Err(CmdError::Cache(error));
    }
    tracing::debug!(child_pid, "run recovery entry transitioned to running");

    let status = child.wait();
    #[cfg(unix)]
    forwarder.stop();
    let code = match status {
        Ok(status) => {
            let code = child_exit_code(status);
            tracing::debug!(child_pid, exit_code = code, "run child process exited");
            code
        }
        Err(error) => {
            tracing::warn!("failed to wait for run child: {error}");
            1
        }
    };
    let report = cleanup(
        &client,
        &config,
        &cache_dir,
        CleanupScope::ReleasedRun(&ReleasedRun {
            cache_key: pending.cache_key,
            run_id: pending.run_id,
            wrapper_pid,
            child_pid,
        }),
        OffsetDateTime::now_utc(),
    );
    report_cleanup(child_pid, report);
    Ok(code)
}

fn render_command_line(command: &[std::ffi::OsString]) -> String {
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

fn report_cleanup(
    child_pid: u32,
    report: Result<crate::token::cleanup::CleanupReport, crate::cache::CacheError>,
) {
    match report {
        Ok(report) if report.is_complete() => {
            tracing::debug!(
                child_pid,
                "run token was remotely revoked and recovery state deleted"
            );
        }
        Ok(report) => {
            tracing::debug!(child_pid, report = ?report, "run token cleanup was incomplete");
            eprintln!(
                "Warning: run token cleanup was incomplete; recovery state was retained for `ghst prune`"
            );
        }
        Err(error) => {
            tracing::debug!(child_pid, error = %error, "run token cleanup failed");
            eprintln!(
                "Warning: run token cleanup was incomplete; recovery state was retained for `ghst prune`"
            );
        }
    }
}

fn spawn_command(cmd: &RunCmd, token: &str) -> std::io::Result<std::process::Child> {
    let mut command = Command::new(&cmd.command[0]);
    command
        .args(&cmd.command[1..])
        .env("GH_TOKEN", token)
        .env("GITHUB_TOKEN", token)
        .env_remove("GH_ENTERPRISE_TOKEN")
        .env_remove("GITHUB_ENTERPRISE_TOKEN")
        .spawn()
}

fn cleanup_before_handoff(
    client: &GitHubClient,
    config: &crate::config::Config,
    cache_dir: &std::path::Path,
    pending: &PendingRun,
    child_pid: Option<u32>,
) {
    let report = mark_pending_run_for_cleanup(
        cache_dir,
        &pending.cache_key,
        &pending.run_id,
        pending.wrapper_pid,
        child_pid,
    )
    .map(|entry| cleanup_marked_run(client, config, cache_dir, &pending.cache_key, &entry));
    match report {
        Ok(report) if report.is_complete() => {
            tracing::debug!("pending run token was cleaned up before child handoff");
        }
        Ok(report) => {
            tracing::debug!(report = ?report, "pending run token cleanup was incomplete before child handoff");
            eprintln!(
                "Warning: run token cleanup was incomplete; recovery state was retained for `ghst prune`"
            );
        }
        Err(error) => {
            tracing::debug!(error = %error, "failed to mark pending run token for cleanup");
            eprintln!(
                "Warning: run token cleanup was incomplete; recovery state was retained for `ghst prune`"
            );
        }
    }
}

fn terminate_and_wait(child: &mut std::process::Child) {
    if let Err(error) = child.kill() {
        tracing::warn!("failed to terminate untracked run child: {error}");
    }
    if let Err(error) = child.wait() {
        tracing::warn!("failed to wait for untracked run child: {error}");
    }
}

#[cfg(unix)]
fn child_exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => code,
        (None, Some(signal)) => 128 + signal,
        (None, None) => 1,
    }
}

#[cfg(not(unix))]
fn child_exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

#[cfg(unix)]
struct Forwarder(signal_hook::iterator::Signals);

#[cfg(unix)]
impl Forwarder {
    fn prepare() -> std::io::Result<Self> {
        use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
        signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP, SIGQUIT]).map(Self)
    }

    fn start(mut self, child_pid: u32) -> std::io::Result<ActiveForwarder> {
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
        Ok(ActiveForwarder { handle, thread })
    }
}

#[cfg(unix)]
struct ActiveForwarder {
    handle: signal_hook::iterator::Handle,
    thread: std::thread::JoinHandle<()>,
}

#[cfg(unix)]
impl ActiveForwarder {
    fn stop(self) {
        self.handle.close();
        if self.thread.join().is_err() {
            tracing::warn!("run signal-forwarding thread panicked");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn command(parts: &[&str]) -> RunCmd {
        RunCmd {
            profile: None,
            repo: Vec::new(),
            command: parts.iter().map(OsString::from).collect(),
        }
    }

    #[test]
    fn child_environment_is_replaced_and_arguments_are_preserved() {
        let cmd = command(&[
            "sh",
            "-c",
            "test \"$GH_TOKEN\" = fresh && test \"$GITHUB_TOKEN\" = fresh && test -z \"$GH_ENTERPRISE_TOKEN\" && test -z \"$GITHUB_ENTERPRISE_TOKEN\" && test \"$1\" = 'a b'",
            "sh",
            "a b",
        ]);
        let status = spawn_command(&cmd, "fresh").unwrap().wait().unwrap();
        assert_eq!(child_exit_code(status), 0);
    }

    #[test]
    fn rendered_command_line_cannot_inject_status_lines() {
        let command = command(&["printf", "first\n    Lifetime: Fake"]);
        assert_eq!(
            render_command_line(&command.command),
            r#"printf "first\n    Lifetime: Fake""#
        );
    }

    #[test]
    fn child_exit_codes_and_signals_are_mapped() {
        let status = spawn_command(&command(&["sh", "-c", "exit 37"]), "token")
            .unwrap()
            .wait()
            .unwrap();
        assert_eq!(child_exit_code(status), 37);
        #[cfg(unix)]
        {
            let status = spawn_command(&command(&["sh", "-c", "kill -TERM $$"]), "token")
                .unwrap()
                .wait()
                .unwrap();
            assert_eq!(child_exit_code(status), 143);
        }
    }
}
