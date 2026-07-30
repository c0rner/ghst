use ghst::cli::{GhstCli, SubCommand};
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
    info!("Executing ghst CLI");

    match args.command {
        SubCommand::Login(cmd) => info!("Command: login (profile: {:?})", cmd.profile),
        SubCommand::Token(cmd) => info!(
            "Command: token (profile: {:?}, repo: {:?}, format: {:?})",
            cmd.profile, cmd.repo, cmd.format
        ),
        SubCommand::Status(_) => info!("Command: status"),
        SubCommand::Profiles(_) => info!("Command: profiles"),
        SubCommand::Clear(_) => info!("Command: clear"),
        SubCommand::Proxy(cmd) => info!(
            "Command: proxy (socket: {:?}, allow_profile: {:?})",
            cmd.socket, cmd.allow_profile
        ),
    }
}
