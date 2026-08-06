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

    let result = match &args.command {
        SubCommand::Login(cmd) => cmd::login::run_login(&args, cmd),
        SubCommand::Profiles(cmd) => cmd::profiles::run_profiles(&args, cmd),
        SubCommand::Token(cmd) => cmd::token::run_token(&args, cmd),
        SubCommand::Status(cmd) => cmd::status::run_status(&args, cmd),
        SubCommand::Clear(cmd) => cmd::clear::run_clear(&args, cmd),
        SubCommand::Proxy(cmd) => cmd::proxy::run_proxy(&args, cmd),
    };

    if let Err(err) = result {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}
