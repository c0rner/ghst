use crate::cmd::{GhstCli, TokenCmd};
use tracing::info;

/// Handles execution of the `ghst token` subcommand.
///
/// # Errors
///
/// Returns an error string if token retrieval or minting fails.
#[allow(clippy::unnecessary_wraps)]
pub fn run_token(_args: &GhstCli, cmd: &TokenCmd) -> Result<(), String> {
    info!(
        "Command: token (profile: {:?}, repo: {:?}, format: {:?})",
        cmd.profile, cmd.repo, cmd.format
    );
    Ok(())
}
