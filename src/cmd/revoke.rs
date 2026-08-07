use crate::cmd::{CmdError, GhstCli, RevokeCmd};
use crate::github::GitHubClient;
use crate::token::revoke::{RevokeFailure, RevokeReport};
use std::io::{self, Write};

pub fn run_revoke(args: &GhstCli, cmd: &RevokeCmd) -> Result<(), CmdError> {
    if !cmd.all {
        return Err(CmdError::RevokeAllRequired);
    }
    let config = crate::config::load(args.config.as_deref())?;
    let cache_dir = crate::config::cache_dir()?;
    let report = crate::token::revoke::revoke_all(
        &GitHubClient::new(),
        &config,
        &cache_dir,
        time::OffsetDateTime::now_utc(),
    )?;
    write_report(&mut io::stdout().lock(), &report)?;
    if report.failures.is_empty() {
        Ok(())
    } else {
        Err(CmdError::RevokeIncomplete {
            failures: report.failures.len(),
        })
    }
}

fn write_report(writer: &mut impl Write, report: &RevokeReport) -> io::Result<()> {
    writeln!(writer, "Credential revocation report:")?;
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
            RevokeFailure::MissingAppCredentials { entry } => writeln!(
                writer,
                "  - {entry}: configured root unavailable; deleted locally and token may remain active remotely"
            )?,
            RevokeFailure::ClientSecretUnavailable { entry } => writeln!(
                writer,
                "  - {entry}: client secret unavailable; deleted locally and token may remain active remotely"
            )?,
            RevokeFailure::GitHubRevocation { entry, source: _ } => {
                writeln!(writer, "  - {entry}: remote revocation failed")?;
            }
            RevokeFailure::CacheDeletion { entry, source } => {
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
        let report = RevokeReport {
            remotely_inactive: 1,
            local_only: 2,
            retained: 0,
            failures: Vec::new(),
        };
        let mut output = Vec::new();
        write_report(&mut output, &report).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "Credential revocation report:\n  Remotely revoked or already inactive: 1\n  Deleted locally only: 2\n  Retained for retry: 0\n  Failures: 0\n"
        );
    }

    #[test]
    fn all_acknowledgement_is_required_before_loading_configuration() {
        let args = GhstCli {
            config: Some("missing.toml".into()),
            command: crate::cmd::SubCommand::Revoke(RevokeCmd { all: false }),
        };
        let error = run_revoke(&args, &RevokeCmd { all: false }).unwrap_err();
        assert!(matches!(error, CmdError::RevokeAllRequired));
    }
}
