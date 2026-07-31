mod browser;
mod cache;
mod cli;
mod commands;
mod config;
mod git;
mod github;

use cli::{GhstCli, SubCommand};
use tracing::info;
use tracing_subscriber::EnvFilter;

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

fn main() {
    init_logging();

    let args: GhstCli = argh::from_env();

    match &args.command {
        SubCommand::Login(cmd) => {
            if let Err(err) = commands::run_login(&args, cmd) {
                eprintln!("Error: {err}");
                std::process::exit(1);
            }
        }
        SubCommand::Token(cmd) => info!(
            "Command: token (profile: {:?}, repo: {:?}, format: {:?})",
            cmd.profile, cmd.repo, cmd.format
        ),
        SubCommand::Status(_) => info!("Command: status"),
        SubCommand::Profiles(cmd) => {
            let config_result = args
                .config
                .as_ref()
                .map_or_else(config::Config::load, |path| {
                    config::Config::load_from_path(path)
                });

            match config_result {
                Ok(cfg) => {
                    if let Err(err) =
                        config::print_profiles(&mut std::io::stdout(), &cfg, cmd.verbose)
                    {
                        eprintln!("Error writing profiles: {err}");
                        std::process::exit(1);
                    }
                }
                Err(err) => {
                    eprintln!("Error loading configuration: {err}");
                    std::process::exit(1);
                }
            }
        }
        SubCommand::Clear(_) => info!("Command: clear"),
        SubCommand::Proxy(cmd) => info!(
            "Command: proxy (socket: {:?}, allow_profile: {:?})",
            cmd.socket, cmd.allow_profile
        ),
    }
}
