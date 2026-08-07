mod browser;
mod cache;
mod cmd;
mod config;
mod git;
mod github;
mod repository;
mod token;

use cmd::{GhstCli, SubCommand};
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

    let exit_code = match &args.command {
        SubCommand::Run(cmd) => match cmd::run::run_run(&args, cmd) {
            cmd::run::RunOutcome::ChildExit(code) => code,
            cmd::run::RunOutcome::GhstError(error) => {
                eprintln!("Error: {error}");
                1
            }
        },
        SubCommand::Login(cmd) => command_exit(cmd::login::run_login(&args, cmd)),
        SubCommand::Profiles(cmd) => command_exit(cmd::profiles::run_profiles(&args, cmd)),
        SubCommand::Token(cmd) => command_exit(cmd::token::run_token(&args, cmd)),
        SubCommand::Status(cmd) => command_exit(cmd::status::run_status(&args, cmd)),
        SubCommand::Revoke(cmd) => command_exit(cmd::revoke::run_revoke(&args, cmd)),
        SubCommand::Prune(cmd) => command_exit(cmd::prune::run_prune(&args, cmd)),
    };

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

fn command_exit(result: Result<(), cmd::CmdError>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("Error: {error}");
            1
        }
    }
}
