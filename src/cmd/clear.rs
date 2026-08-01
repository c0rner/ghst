use crate::cmd::{ClearCmd, CmdError, GhstCli};
use tracing::info;

/// Handles execution of the `ghst clear` subcommand.
///
/// # Errors
///
/// Returns `CmdError` if clearing cached tokens fails.
#[allow(clippy::unnecessary_wraps)]
pub fn run_clear(_args: &GhstCli, _cmd: &ClearCmd) -> Result<(), CmdError> {
    info!("Command: clear");
    Ok(())
}
