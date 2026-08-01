use crate::cmd::{CmdError, GhstCli, ProxyCmd};
use tracing::info;

/// Handles execution of the `ghst proxy` subcommand.
///
/// # Errors
///
/// Returns `CmdError` if running proxy daemon fails.
#[allow(clippy::unnecessary_wraps)]
pub fn run_proxy(_args: &GhstCli, cmd: &ProxyCmd) -> Result<(), CmdError> {
    info!(
        "Command: proxy (socket: {:?}, allow_profile: {:?})",
        cmd.socket, cmd.allow_profile
    );
    Ok(())
}
