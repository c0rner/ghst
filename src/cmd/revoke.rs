use crate::cmd::{CmdError, GhstCli, RevokeCmd};
use crate::github::GitHubClient;
use crate::token::revoke::{RevokeFailure, RevokeOneOutcome, RevokeReport};
use std::io::{self, Write};

pub fn run_revoke(args: &GhstCli, cmd: &RevokeCmd) -> Result<(), CmdError> {
    let selection = selection(cmd)?;
    let config = crate::config::load(args.config.as_deref())?;
    let app_registrations = config.app_registrations();
    let cache_dir = crate::config::cache_dir()?;
    let store = crate::cache::CacheStore::new(&cache_dir);
    let now = time::OffsetDateTime::now_utc();
    let client = GitHubClient::new();
    let report = match selection {
        RevokeSelection::All => {
            tracing::debug!(cache_dir = %cache_dir.display(), "revoking all cached credentials");
            crate::token::revoke::revoke_all(&client, &app_registrations, &store, now)?
        }
        RevokeSelection::One(id) => {
            tracing::debug!(cache_dir = %cache_dir.display(), cache_id = id, "revoking cached credential");
            match crate::token::revoke::revoke_one(&client, &app_registrations, &store, id, now)? {
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

fn write_report<E: std::fmt::Display>(
    writer: &mut impl Write,
    report: &RevokeReport<E>,
) -> io::Result<()> {
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
            RevokeFailure::InvalidEntry { entry } => writeln!(
                writer,
                "  - {entry}: invalid or corrupt cache entry; retained without deletion or remote revocation"
            )?,
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
            RevokeFailure::CacheDeletion {
                entry,
                source,
                remotely_inactive,
            } => {
                if *remotely_inactive {
                    writeln!(
                        writer,
                        "  - {entry}: local deletion failed: {source}; selected token was revoked or confirmed inactive remotely, but cached file was retained"
                    )?;
                } else {
                    writeln!(
                        writer,
                        "  - {entry}: local deletion failed: {source}; cached file was retained without remote revocation (token was not confirmed inactive remotely and may remain active)"
                    )?;
                }
            }
            RevokeFailure::DirectorySyncFailed {
                entry,
                source,
                remotely_inactive,
            } => {
                if *remotely_inactive {
                    writeln!(
                        writer,
                        "  - {entry}: directory sync failed after local deletion: {source}; selected token was revoked or confirmed inactive remotely, but local deletion durability is uncertain"
                    )?;
                } else {
                    writeln!(
                        writer,
                        "  - {entry}: directory sync failed after local deletion: {source}; local deletion durability is uncertain and token was not revoked or confirmed inactive remotely"
                    )?;
                }
            }
            RevokeFailure::DeletedRecordChanged {
                entry,
                remotely_inactive,
            } => {
                if *remotely_inactive {
                    writeln!(
                        writer,
                        "  - {entry}: cache entry changed concurrently during revocation; selected token was revoked or confirmed inactive remotely, but newer entry was retained"
                    )?;
                } else {
                    writeln!(
                        writer,
                        "  - {entry}: cache entry changed concurrently during revocation; retained without remote revocation (token was not confirmed inactive remotely and may remain active)"
                    )?;
                }
            }
            RevokeFailure::DeletedRecordMissing {
                entry,
                remotely_inactive,
            } => {
                if *remotely_inactive {
                    writeln!(
                        writer,
                        "  - {entry}: cache entry disappeared during revocation; selected token was revoked or confirmed inactive remotely"
                    )?;
                } else {
                    writeln!(
                        writer,
                        "  - {entry}: cache entry disappeared during revocation; token was not revoked or confirmed inactive remotely and may remain active"
                    )?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CacheError;

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

    #[test]
    fn write_report_success_summary() {
        let report: RevokeReport<CacheError> = RevokeReport {
            remotely_inactive: 2,
            local_only: 1,
            retained: 0,
            failures: Vec::new(),
        };
        let mut output = Vec::new();
        write_report(&mut output, &report).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert_eq!(
            text,
            "Credential revocation report:\n  Remotely revoked or already inactive: 2\n  Deleted locally only: 1\n  Retained for retry: 0\n  Failures: 0\n"
        );
    }

    #[test]
    fn write_report_all_failure_variants() {
        use crate::token::RemoteError;

        let failures = vec![
            RevokeFailure::InvalidEntry {
                entry: "entry_invalid".into(),
            },
            RevokeFailure::MissingAppCredentials {
                entry: "entry_missing_app".into(),
            },
            RevokeFailure::ClientSecretUnavailable {
                entry: "entry_no_secret".into(),
            },
            RevokeFailure::AuthorityMismatch {
                entry: "entry_auth_mismatch".into(),
            },
            RevokeFailure::GitHubRevocation {
                entry: "entry_remote_fail".into(),
                source: RemoteError::Http {
                    status: 500,
                    message: "server error".into(),
                },
            },
            RevokeFailure::CacheDeletion {
                entry: "entry_del_fail_remote_ok".into(),
                source: CacheError::io("path1", std::io::Error::other("del error")),
                remotely_inactive: true,
            },
            RevokeFailure::CacheDeletion {
                entry: "entry_del_fail_local_only".into(),
                source: CacheError::io("path2", std::io::Error::other("del error")),
                remotely_inactive: false,
            },
            RevokeFailure::DirectorySyncFailed {
                entry: "entry_sync_remote_ok".into(),
                source: CacheError::io("path3", std::io::Error::other("sync error")),
                remotely_inactive: true,
            },
            RevokeFailure::DirectorySyncFailed {
                entry: "entry_sync_local_only".into(),
                source: CacheError::io("path4", std::io::Error::other("sync error")),
                remotely_inactive: false,
            },
            RevokeFailure::DeletedRecordChanged {
                entry: "entry_changed_remote_ok".into(),
                remotely_inactive: true,
            },
            RevokeFailure::DeletedRecordChanged {
                entry: "entry_changed_local_only".into(),
                remotely_inactive: false,
            },
            RevokeFailure::DeletedRecordMissing {
                entry: "entry_missing_remote_ok".into(),
                remotely_inactive: true,
            },
            RevokeFailure::DeletedRecordMissing {
                entry: "entry_missing_local_only".into(),
                remotely_inactive: false,
            },
        ];

        let count = failures.len();
        let report = RevokeReport {
            remotely_inactive: 0,
            local_only: 0,
            retained: 4,
            failures,
        };
        let mut output = Vec::new();
        write_report(&mut output, &report).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.starts_with(&format!(
            "Credential revocation report:\n  Remotely revoked or already inactive: 0\n  Deleted locally only: 0\n  Retained for retry: 4\n  Failures: {count}\n"
        )));
        assert!(text.contains("  - entry_invalid: invalid or corrupt cache entry; retained without deletion or remote revocation\n"));
        assert!(text.contains("  - entry_missing_app: configured app profile unavailable; deleted locally and token may remain active remotely\n"));
        assert!(text.contains("  - entry_no_secret: client secret unavailable; deleted locally and token may remain active remotely\n"));
        assert!(text.contains("  - entry_auth_mismatch: cached token authority does not match configuration; deleted locally and token may remain active remotely\n"));
        assert!(text.contains("  - entry_remote_fail: remote revocation failed\n"));
        assert!(text.contains("  - entry_del_fail_remote_ok: local deletion failed: cache IO error for 'path1': del error; selected token was revoked or confirmed inactive remotely, but cached file was retained\n"));
        assert!(text.contains("  - entry_del_fail_local_only: local deletion failed: cache IO error for 'path2': del error; cached file was retained without remote revocation (token was not confirmed inactive remotely and may remain active)\n"));
        assert!(text.contains("  - entry_sync_remote_ok: directory sync failed after local deletion: cache IO error for 'path3': sync error; selected token was revoked or confirmed inactive remotely, but local deletion durability is uncertain\n"));
        assert!(text.contains("  - entry_sync_local_only: directory sync failed after local deletion: cache IO error for 'path4': sync error; local deletion durability is uncertain and token was not revoked or confirmed inactive remotely\n"));
        assert!(text.contains("  - entry_changed_remote_ok: cache entry changed concurrently during revocation; selected token was revoked or confirmed inactive remotely, but newer entry was retained\n"));
        assert!(text.contains("  - entry_changed_local_only: cache entry changed concurrently during revocation; retained without remote revocation (token was not confirmed inactive remotely and may remain active)\n"));
        assert!(text.contains("  - entry_missing_remote_ok: cache entry disappeared during revocation; selected token was revoked or confirmed inactive remotely\n"));
        assert!(text.contains("  - entry_missing_local_only: cache entry disappeared during revocation; token was not revoked or confirmed inactive remotely and may remain active\n"));
    }
}
