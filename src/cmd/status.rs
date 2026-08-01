use crate::cmd::{GhstCli, StatusCmd};
use tracing::info;

/// Handles execution of the `ghst status` subcommand.
///
/// # Errors
///
/// Returns an error string if checking status fails.
#[allow(clippy::unnecessary_wraps)]
pub fn run_status(_args: &GhstCli, _cmd: &StatusCmd) -> Result<(), String> {
    info!("Command: status");
    Ok(())
}
