use crate::cmd::{ClearCmd, GhstCli};
use tracing::info;

/// Handles execution of the `ghst clear` subcommand.
///
/// # Errors
///
/// Returns an error string if clearing cached tokens fails.
#[allow(clippy::unnecessary_wraps)]
pub fn run_clear(_args: &GhstCli, _cmd: &ClearCmd) -> Result<(), String> {
    info!("Command: clear");
    Ok(())
}
