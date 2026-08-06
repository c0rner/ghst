use crate::cmd::{ClearCmd, CmdError, GhstCli};
use crate::github::GitHubClient;
use crate::token::clear::{ClearFailure, ClearReport};
use std::io::{self, Write};

pub fn run_clear(args: &GhstCli, _cmd: &ClearCmd) -> Result<(), CmdError> {
    let config = crate::config::load(args.config.as_deref())?;
    let cache_dir = crate::config::cache_dir()?;
    let report = crate::token::clear::clear(
        &GitHubClient::new(),
        &config,
        &cache_dir,
        time::OffsetDateTime::now_utc(),
    )?;
    write_report(&mut io::stdout().lock(), &report)?;
    if report.failures.is_empty() {
        Ok(())
    } else {
        Err(CmdError::ClearIncomplete {
            failures: report.failures.len(),
        })
    }
}

fn write_report(writer: &mut impl Write, report: &ClearReport) -> io::Result<()> {
    writeln!(writer, "Cache clear report:")?;
    writeln!(
        writer,
        "  Remotely revoked or already inactive: {}",
        report.remotely_inactive
    )?;
    writeln!(writer, "  Deleted locally only: {}", report.local_only)?;
    writeln!(writer, "  Retained for retry: {}", report.retained)?;
    writeln!(writer, "  Failures: {}", report.failures.len())?;
    for failure in &report.failures {
        match failure {
            ClearFailure::MissingAppCredentials { entry } => writeln!(
                writer,
                "  - {entry}: configured root unavailable; deleted locally and token may remain active remotely"
            )?,
            ClearFailure::ClientSecretUnavailable { entry } => writeln!(
                writer,
                "  - {entry}: client secret unavailable; deleted locally and token may remain active remotely"
            )?,
            ClearFailure::GitHubRevocation { entry, source: _ } => {
                writeln!(writer, "  - {entry}: remote revocation failed")?;
            }
            ClearFailure::CacheDeletion { entry, source } => {
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
    fn report_format_is_stable() {
        let report = ClearReport {
            remotely_inactive: 1,
            local_only: 2,
            retained: 0,
            failures: Vec::new(),
        };
        let mut output = Vec::new();
        write_report(&mut output, &report).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "Cache clear report:\n  Remotely revoked or already inactive: 1\n  Deleted locally only: 2\n  Retained for retry: 0\n  Failures: 0\n"
        );
    }
}
