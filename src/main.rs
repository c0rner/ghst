mod browser;
mod cache;
mod cmd;
mod config;
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
    init_logging();

    let args: GhstCli = argh::from_env();
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
