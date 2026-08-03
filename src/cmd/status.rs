use crate::cache::{CacheEntry, CacheInspectionState, format_rfc3339, inspect_cache};
use crate::cmd::{CmdError, GhstCli, StatusCmd, load_config};
use crate::config::Config;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use time::OffsetDateTime;
use tracing::info;

pub fn run_status(args: &GhstCli, _cmd: &StatusCmd) -> Result<(), CmdError> {
    let config = load_config(args.config.as_deref())?;
    let cache_dir = Config::cache_dir()?;
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
    let mut grouped: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut unmatched = Vec::new();
    for (index, inspection) in inspections.iter().enumerate() {
        match &inspection.state {
            CacheInspectionState::Current(entry) | CacheInspectionState::Unsupported(entry)
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
        writeln!(writer, "{marker} {name} [{}]", profile.kind())?;
        match grouped.remove(name.as_str()) {
            Some(indices) => {
                for index in indices {
                    write_entry(writer, &inspections[index], now)?;
                }
            }
            None => writeln!(writer, "    Lifetime:    Not cached")?,
        }
        writeln!(writer)?;
    }
    for index in unmatched {
        writeln!(writer, "  Unmatched Entry [{}]", inspections[index].label)?;
        write_entry(writer, &inspections[index], now)?;
        writeln!(writer)?;
    }
    Ok(())
}

fn write_entry(
    writer: &mut impl Write,
    inspection: &crate::cache::CacheInspection,
    now: OffsetDateTime,
) -> io::Result<()> {
    match &inspection.state {
        CacheInspectionState::Invalid => writeln!(writer, "    Lifetime:    Invalid"),
        CacheInspectionState::Unsupported(entry) => {
            writeln!(writer, "    Lifetime:    Unsupported")?;
            writeln!(writer, "    Repo Scope:  {}", entry.repo_scope())
        }
        CacheInspectionState::Current(entry) => {
            let expiry = match entry {
                CacheEntry::Root(value) => value.expires_at,
                CacheEntry::Derived(value) => value.expires_at,
            };
            let state = if expiry.value() <= now {
                "Expired"
            } else if expiry.is_usable_at(now) {
                "Usable"
            } else {
                "Expiring"
            };
            writeln!(writer, "    Lifetime:    {state}")?;
            writeln!(writer, "    Repo Scope:  {}", entry.repo_scope())?;
            writeln!(
                writer,
                "    Expires:     {}",
                format_rfc3339(expiry.value())
            )
        }
    }
}
