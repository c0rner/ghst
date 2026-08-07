use crate::cmd::{CmdError, GhstCli, PruneCmd};
use crate::github::GitHubClient;
use crate::token::cleanup::{CleanupFailure, CleanupReport, CleanupScope};
use std::io::{self, Write};

pub fn run_prune(args: &GhstCli, _cmd: &PruneCmd) -> Result<(), CmdError> {
    let config = crate::config::load(args.config.as_deref())?;
    let cache_dir = crate::config::cache_dir()?;
    let report = crate::token::cleanup::cleanup(
        &GitHubClient::new(),
        &config,
        &cache_dir,
        CleanupScope::Prune,
        time::OffsetDateTime::now_utc(),
    )?;
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
            CleanupFailure::UnsupportedEntry { entry } => {
                writeln!(writer, "  - {entry}: unsupported cache entry retained")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_report_format_is_stable() {
        let report = CleanupReport {
            expired_deletions: 1,
            revoked_runs: 2,
            active_runs_skipped: 3,
            retained_entries: 0,
            failures: Vec::new(),
        };
        let mut output = Vec::new();
        write_report(&mut output, &report).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "Cache prune report:\n  Expired entries deleted: 1\n  Run tokens revoked or inactive: 2\n  Active runs skipped: 3\n  Entries retained: 0\n  Failures: 0\n"
        );
    }
}
