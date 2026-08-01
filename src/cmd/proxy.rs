use crate::cmd::{GhstCli, ProxyCmd};
use tracing::info;

/// Handles execution of the `ghst proxy` subcommand.
///
/// # Errors
///
/// Returns an error string if running proxy daemon fails.
#[allow(clippy::unnecessary_wraps)]
pub fn run_proxy(_args: &GhstCli, cmd: &ProxyCmd) -> Result<(), String> {
    info!(
        "Command: proxy (socket: {:?}, allow_profile: {:?})",
        cmd.socket, cmd.allow_profile
    );
    Ok(())
}
