use crate::cmd::{CmdError, GhstCli, RevokeCmd};
use crate::github::GitHubClient;
use crate::token::revoke::{RevokeFailure, RevokeOneOutcome, RevokeReport};
use std::io::{self, Write};

pub fn run_revoke(args: &GhstCli, cmd: &RevokeCmd) -> Result<(), CmdError> {
    let selection = selection(cmd)?;
    let config = crate::config::load(args.config.as_deref())?;
    let cache_dir = crate::config::cache_dir()?;
    let now = time::OffsetDateTime::now_utc();
    let client = GitHubClient::new();
    let report = match selection {
        RevokeSelection::All => {
            tracing::debug!(cache_dir = %cache_dir.display(), "revoking all cached credentials");
            crate::token::revoke::revoke_all(&client, &config, &cache_dir, now)?
        }
        RevokeSelection::One(id) => {
            tracing::debug!(cache_dir = %cache_dir.display(), cache_id = id, "revoking cached credential");
            match crate::token::revoke::revoke_one(&client, &config, &cache_dir, id, now)? {
                RevokeOneOutcome::Revoked(report) => report,
                RevokeOneOutcome::NotFound => {
                    return Err(CmdError::RevokeTargetNotFound(id.to_owned()));
                }
                RevokeOneOutcome::Ambiguous => {
                    return Err(CmdError::RevokeTargetAmbiguous(id.to_owned()));
                }
            }
        }
    };
    tracing::debug!(
        remotely_inactive = report.remotely_inactive,
        local_only = report.local_only,
        retained = report.retained,
        failures = report.failures.len(),
        "credential revocation completed"
    );
    write_report(&mut io::stdout().lock(), &report)?;
    if report.failures.is_empty() {
        Ok(())
    } else {
        Err(CmdError::RevokeIncomplete {
            failures: report.failures.len(),
        })
    }
}

#[derive(Clone, Copy)]
enum RevokeSelection<'a> {
    All,
    One(&'a str),
}

fn selection(cmd: &RevokeCmd) -> Result<RevokeSelection<'_>, CmdError> {
    match (cmd.all, cmd.id.as_deref()) {
        (true, None) => Ok(RevokeSelection::All),
        (false, Some(id)) if valid_id(id) => Ok(RevokeSelection::One(id)),
        (false, Some(_)) => Err(CmdError::InvalidRevokeId),
        (false, None) => Err(CmdError::RevokeSelectionRequired),
        (true, Some(_)) => Err(CmdError::RevokeSelectionConflict),
    }
}

fn valid_id(id: &str) -> bool {
    (crate::cache::MIN_CACHE_ID_LENGTH..=64).contains(&id.len())
        && id.bytes().all(|byte| byte.is_ascii_hexdigit())
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
                "  - {entry}: configured app profile unavailable; deleted locally and token may remain active remotely"
            )?,
            RevokeFailure::ClientSecretUnavailable { entry } => writeln!(
                writer,
                "  - {entry}: client secret unavailable; deleted locally and token may remain active remotely"
            )?,
            RevokeFailure::AuthorityMismatch { entry } => writeln!(
                writer,
                "  - {entry}: cached token authority does not match configuration; deleted locally and token may remain active remotely"
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
    fn selection_is_validated_before_loading_configuration() {
        let args = GhstCli {
            config: Some("missing.toml".into()),
            version: false,
            command: crate::cmd::SubCommand::Revoke(RevokeCmd {
                id: None,
                all: false,
            }),
        };
        let error = run_revoke(
            &args,
            &RevokeCmd {
                id: None,
                all: false,
            },
        )
        .unwrap_err();
        assert!(matches!(error, CmdError::RevokeSelectionRequired));

        assert!(matches!(
            selection(&RevokeCmd {
                id: Some("short".into()),
                all: false,
            }),
            Err(CmdError::InvalidRevokeId)
        ));
        assert!(matches!(
            selection(&RevokeCmd {
                id: Some("0123456".into()),
                all: false,
            }),
            Ok(RevokeSelection::One("0123456"))
        ));
        assert!(matches!(
            selection(&RevokeCmd {
                id: Some("0".repeat(64)),
                all: true,
            }),
            Err(CmdError::RevokeSelectionConflict)
        ));
    }
}
