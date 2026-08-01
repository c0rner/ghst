use crate::cmd::{CmdError, GhstCli, StatusCmd};
use tracing::info;

/// Handles execution of the `ghst status` subcommand.
///
/// # Errors
///
/// Returns `CmdError` if checking status fails.
#[allow(clippy::unnecessary_wraps)]
pub fn run_status(_args: &GhstCli, _cmd: &StatusCmd) -> Result<(), CmdError> {
    info!("Command: status");
    Ok(())
}
