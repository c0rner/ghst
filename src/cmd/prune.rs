use crate::cmd::{CmdError, GhstCli, PruneCmd};
use crate::github::GitHubClient;
use crate::token::cleanup::{CleanupFailure, CleanupReport, CleanupScope};
use std::io::{self, Write};

pub fn run_prune(args: &GhstCli, _cmd: &PruneCmd) -> Result<(), CmdError> {
    let config = crate::config::load(args.config.as_deref())?;
    let cache_dir = crate::config::cache_dir()?;
    tracing::debug!(cache_dir = %cache_dir.display(), "pruning expired and abandoned cache entries");
    let report = crate::token::cleanup::cleanup(
        &GitHubClient::new(),
        &config,
        &cache_dir,
        CleanupScope::Prune,
        time::OffsetDateTime::now_utc(),
    )?;
    tracing::debug!(
        expired_deletions = report.expired_deletions,
        revoked_runs = report.revoked_runs,
        active_runs_skipped = report.active_runs_skipped,
        retained_entries = report.retained_entries,
        failures = report.failures.len(),
        "cache pruning completed"
    );
    write_report(&mut io::stdout().lock(), &report)?;
    if report.is_complete() {
        Ok(())
    } else {
        Err(CmdError::PruneIncomplete {
            failures: report.failures.len(),
        })
    }
}

fn write_report(writer: &mut impl Write, report: &CleanupReport) -> io::Result<()> {
    writeln!(writer, "Cache prune report:")?;
    writeln!(
        writer,
        "  Expired entries deleted: {}",
        report.expired_deletions
    )?;
    writeln!(
        writer,
        "  Run tokens revoked or inactive: {}",
        report.revoked_runs
    )?;
    writeln!(
        writer,
        "  Active runs skipped: {}",
        report.active_runs_skipped
    )?;
    writeln!(writer, "  Entries retained: {}", report.retained_entries)?;
    writeln!(writer, "  Failures: {}", report.failures.len())?;
    for failure in &report.failures {
        match failure {
            CleanupFailure::InvalidEntry { entry } => {
                writeln!(writer, "  - {entry}: invalid cache entry retained")?;
            }
            CleanupFailure::Configuration { entry } => {
                writeln!(
                    writer,
                    "  - {entry}: source authority could not be validated"
                )?;
            }
            CleanupFailure::ClientSecretUnavailable { entry } => {
                writeln!(writer, "  - {entry}: client secret unavailable")?;
            }
            CleanupFailure::Ownership { entry, source: _ } => {
                writeln!(writer, "  - {entry}: run ownership or lifecycle changed")?;
            }
            CleanupFailure::GitHubRevocation { entry, source: _ } => {
                writeln!(writer, "  - {entry}: remote revocation failed")?;
            }
            CleanupFailure::CacheDeletion { entry, source } => {
                writeln!(writer, "  - {entry}: local deletion failed: {source}")?;
            }
        }
    }
    Ok(())
}
