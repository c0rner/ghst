mod browser;
mod cache;
mod cmd;
mod config;
mod domain;
mod git;
mod github;
mod repository;
mod token;

use cmd::{GhstCli, SubCommand};
use tracing::debug;
use tracing_subscriber::EnvFilter;

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

fn main() {
    if is_standalone_version_request(std::env::args_os().skip(1)) {
        println!("{}", version_output());
        return;
    }

    init_logging();

    let args: GhstCli = argh::from_env();
    if args.version {
        println!("{}", version_output());
        return;
    }
    let command = args.command.name();
    debug!(command, "starting command");

    let exit_code = match &args.command {
        SubCommand::Edit(cmd) => command_exit(command, cmd::edit::run_edit(&args, cmd)),
        SubCommand::Run(cmd) => match cmd::run::run_run(&args, cmd) {
            cmd::run::RunOutcome::ChildExit(code) => {
                debug!(command, exit_code = code, "child command completed");
                code
            }
            cmd::run::RunOutcome::GhstError(error) => {
                debug!(command, error = %error, "command failed");
                eprintln!("Error: {error}");
                1
            }
        },
        SubCommand::Login(cmd) => command_exit(command, cmd::login::run_login(&args, cmd)),
        SubCommand::Profiles(cmd) => command_exit(command, cmd::profiles::run_profiles(&args, cmd)),
        SubCommand::Token(cmd) => command_exit(command, cmd::token::run_token(&args, cmd)),
        SubCommand::Status(cmd) => command_exit(command, cmd::status::run_status(&args, cmd)),
        SubCommand::Revoke(cmd) => command_exit(command, cmd::revoke::run_revoke(&args, cmd)),
        SubCommand::Prune(cmd) => command_exit(command, cmd::prune::run_prune(&args, cmd)),
    };

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    debug!(command, "command completed");
}

fn is_standalone_version_request(mut args: impl Iterator<Item = std::ffi::OsString>) -> bool {
    matches!(
        (args.next(), args.next()),
        (Some(argument), None) if argument == "--version"
    )
}

fn version_output() -> String {
    format!("ghst {}", cmd::GHST_VERSION)
}

fn command_exit(command: &str, result: Result<(), cmd::CmdError>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(error) => {
            debug!(command, error = %error, "command failed");
            eprintln!("Error: {error}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_version_request_is_unambiguous() {
        assert_eq!(version_output(), format!("ghst {}", cmd::GHST_VERSION));
        assert!(is_standalone_version_request(
            ["--version".into()].into_iter()
        ));
        assert!(!is_standalone_version_request(
            ["run".into(), "--version".into()].into_iter()
        ));
    }
}
