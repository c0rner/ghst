use crate::cache::{CacheEntry, CacheInspectionState, abbreviate_cache_key, inspect_cache};
use crate::cmd::{CmdError, GhstCli, StatusCmd, format_human_expiry};
use crate::config::Config;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use time::OffsetDateTime;
use tracing::{debug, info};

pub fn run_status(args: &GhstCli, _cmd: &StatusCmd) -> Result<(), CmdError> {
    let config = crate::config::load(args.config.as_deref())?;
    let cache_dir = crate::config::cache_dir()?;
    print_status(
        &mut io::stdout().lock(),
        &config,
        &cache_dir,
        OffsetDateTime::now_utc(),
    )
}

pub fn print_status<W: Write>(
    writer: &mut W,
    config: &Config,
    cache_dir: &Path,
    now: OffsetDateTime,
) -> Result<(), CmdError> {
    let inspections = inspect_cache(cache_dir)?;
    let cache_keys: Vec<_> = inspections
        .iter()
        .filter_map(|inspection| inspection.cache_key.as_deref())
        .collect();
    debug!(cache_dir = %cache_dir.display(), entries = inspections.len(), "inspected token cache for status");
    let mut grouped: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut unmatched = Vec::new();
    for (index, inspection) in inspections.iter().enumerate() {
        match &inspection.state {
            CacheInspectionState::Current(entry)
                if config.profiles.contains_key(entry.profile()) =>
            {
                grouped.entry(entry.profile()).or_default().push(index);
            }
            _ => unmatched.push(index),
        }
    }
    writeln!(writer, "Cached token(s):")?;
    info!("No network request is made; remote revocation cannot be detected.");
    for (name, profile) in &config.profiles {
        let marker = if config.default_profile.as_deref() == Some(name) {
            "*"
        } else {
            " "
        };
        writeln!(writer, "{marker} {name} [{}]", profile.kind_name())?;
        match grouped.remove(name.as_str()) {
            Some(indices) => {
                for (position, index) in indices.into_iter().enumerate() {
                    if position > 0 {
                        writeln!(writer)?;
                    }
                    write_entry(writer, &inspections[index], &cache_keys, now)?;
                }
            }
            None => writeln!(writer, "    Lifetime:    Not cached")?,
        }
        writeln!(writer)?;
    }
    debug!(
        configured_profiles = config.profiles.len(),
        unmatched_entries = unmatched.len(),
        "grouped cached tokens by configured profile"
    );
    for index in unmatched {
        writeln!(writer, "  Unmatched Entry [{}]", inspections[index].label)?;
        write_entry(writer, &inspections[index], &cache_keys, now)?;
        writeln!(writer)?;
    }
    Ok(())
}

fn write_entry(
    writer: &mut impl Write,
    inspection: &crate::cache::CacheInspection,
    cache_keys: &[&str],
    now: OffsetDateTime,
) -> io::Result<()> {
    if let Some(id) = &inspection.cache_key {
        writeln!(
            writer,
            "    ID:          {}",
            abbreviate_cache_key(id, cache_keys)
        )?;
    }
    match &inspection.state {
        CacheInspectionState::Invalid => writeln!(writer, "    Lifetime:    Invalid"),
        CacheInspectionState::Current(entry) => {
            let expiry = match entry.as_ref() {
                CacheEntry::Base(value) => value.expires_at,
                CacheEntry::Scoped(value) => value.expires_at,
                CacheEntry::Run(value) => value.expires_at,
            };
            let state = if expiry.value() <= now {
                "Expired"
            } else if expiry.is_safe_to_handoff_at(now) {
                "Usable"
            } else {
                "Expiring"
            };
            writeln!(writer, "    Lifetime:    {state}")?;
            writeln!(writer, "    Repo Scope:  {}", entry.repo_scope())?;
            if let CacheEntry::Run(entry) = entry.as_ref() {
                let state = match entry.state {
                    crate::cache::RunState::Pending => "Pending".to_owned(),
                    crate::cache::RunState::Running => entry.child_pid.map_or_else(
                        || "Running".to_owned(),
                        |child_pid| format!("Running (PID {child_pid})"),
                    ),
                    crate::cache::RunState::CleanupPending => "Cleanup pending".to_owned(),
                };
                writeln!(writer, "    Run State:   {state}")?;
                if matches!(entry.state, crate::cache::RunState::Running) {
                    writeln!(writer, "    Command:     {}", entry.command)?;
                }
            }
            writeln!(writer, "    Expires:     {}", format_human_expiry(expiry))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{
        AccessToken, CacheEntry, RUN_CACHE_SCHEMA_VERSION, RunCacheEntry, RunState, TokenExpiry,
        authority_fingerprint, compute_run_cache_key, save_cache_entry,
    };
    use time::Duration;

    #[test]
    fn run_status_separates_entries_and_describes_running_sessions() {
        let config: Config = r#"
version = 1
default_profile = "reader"
[profile.developer]
github_app.account = "acme"
github_app.client_id = "id"
github_app.client_secret = "secret"
[profile.reader]
source = "developer"
repo = "acme/api"
permissions = { contents = "read" }
"#
        .parse()
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let now = OffsetDateTime::now_utc();
        let run_id = "status-run";
        save_cache_entry(
            &cache_dir,
            &compute_run_cache_key(run_id),
            &CacheEntry::Run(RunCacheEntry {
                version: RUN_CACHE_SCHEMA_VERSION,
                run_id: run_id.into(),
                state: RunState::Running,
                wrapper_pid: 123_456,
                child_pid: Some(123_457),
                command: "cargo test --workspace".into(),
                profile: "reader".into(),
                source_profile: "developer".into(),
                source_authority_fingerprint: authority_fingerprint("id", "acme"),
                github_user: "octocat".into(),
                repo_scope: "acme/api".into(),
                expires_at: TokenExpiry::new(now + Duration::hours(1)),
                access_token: AccessToken::from("status-secret"),
            }),
        )
        .unwrap();
        save_cache_entry(
            &cache_dir,
            &compute_run_cache_key("second-status-run"),
            &CacheEntry::Run(RunCacheEntry {
                version: RUN_CACHE_SCHEMA_VERSION,
                run_id: "second-status-run".into(),
                state: RunState::CleanupPending,
                wrapper_pid: 223_456,
                child_pid: Some(223_457),
                command: "cargo check".into(),
                profile: "reader".into(),
                source_profile: "developer".into(),
                source_authority_fingerprint: authority_fingerprint("id", "acme"),
                github_user: "octocat".into(),
                repo_scope: "acme/api".into(),
                expires_at: TokenExpiry::new(now + Duration::hours(1)),
                access_token: AccessToken::from("second-status-secret"),
            }),
        )
        .unwrap();
        let mut output = Vec::new();
        print_status(&mut output, &config, &cache_dir, now).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("  developer [base]"));
        assert!(output.contains("* reader [scoped]"));
        assert!(output.contains(&format!(
            "ID:          {}",
            &compute_run_cache_key(run_id)[..crate::cache::MIN_CACHE_ID_LENGTH]
        )));
        assert!(output.contains(&format!(
            "ID:          {}",
            &compute_run_cache_key("second-status-run")[..crate::cache::MIN_CACHE_ID_LENGTH]
        )));
        assert!(output.contains("Run State:   Running (PID 123457)"));
        assert!(!output.contains("Process ID:"));
        assert!(output.contains("Command:     cargo test --workspace"));
        assert!(output.contains("Expires:") && output.contains("\n\n    ID:"));
        assert!(!output.contains("status-secret"));
        assert!(!output.contains("second-status-secret"));
    }
}
