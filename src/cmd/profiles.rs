use crate::cmd::{GhstCli, ProfilesCmd};
use crate::config::{Config, ProfileConfig, RepoScope};
use std::io::{self, Write};

/// Handles execution of the `ghst profiles` subcommand.
///
/// # Errors
///
/// Returns an error string if loading configuration or printing profiles fails.
pub fn run_profiles(args: &GhstCli, cmd: &ProfilesCmd) -> Result<(), String> {
    let config = args
        .config
        .as_ref()
        .map_or_else(Config::load, |path| Config::load_from_path(path))
        .map_err(|err| format!("loading configuration: {err}"))?;

    print_profiles(&mut io::stdout(), &config, cmd.verbose)
        .map_err(|err| format!("writing profiles: {err}"))
}

fn print_profiles<W: Write>(writer: &mut W, config: &Config, verbose: bool) -> io::Result<()> {
    if verbose {
        writeln!(writer, "Configured Profiles:\n")?;
    }

    for (name, profile) in &config.profiles {
        let is_default = config.default_profile.as_deref() == Some(name.as_str());
        let marker = if is_default { "*" } else { " " };
        let default_suffix = if is_default { " (default)" } else { "" };

        if verbose {
            match profile {
                ProfileConfig::Root(root) => {
                    writeln!(writer, "{marker} {name} [root]{default_suffix}")?;
                    writeln!(writer, "    Account:     {}", root.github_app.account)?;
                    writeln!(writer, "    Client ID:   {}", root.github_app.client_id)?;
                    let repo_str = match &root.repo {
                        Some(RepoScope::All) | None => "all",
                        Some(RepoScope::Auto) => "auto",
                        Some(RepoScope::Specific(r)) => r.as_str(),
                    };
                    writeln!(writer, "    Repo Scope:  {repo_str}")?;
                    if let Some(desc) = &root.description {
                        writeln!(writer, "    Description: {desc}")?;
                    }
                }
                ProfileConfig::Derived(derived) => {
                    writeln!(writer, "{marker} {name} [derived]{default_suffix}")?;
                    writeln!(writer, "    Source:      {}", derived.source)?;
                    let repo_str = match &derived.repo {
                        RepoScope::All => "all",
                        RepoScope::Auto => "auto",
                        RepoScope::Specific(r) => r.as_str(),
                    };
                    writeln!(writer, "    Repo Scope:  {repo_str}")?;
                    if !derived.permissions.is_empty() {
                        let perms = derived
                            .permissions
                            .iter()
                            .map(|(k, v)| format!("{k}={v}"))
                            .collect::<Vec<_>>()
                            .join(", ");
                        writeln!(writer, "    Permissions: {perms}")?;
                    }
                    if let Some(desc) = &derived.description {
                        writeln!(writer, "    Description: {desc}")?;
                    }
                }
            }
            writeln!(writer)?;
        } else {
            let kind_str = match profile {
                ProfileConfig::Root(_) => "root",
                ProfileConfig::Derived(_) => "derived",
            };
            let desc_str = match profile {
                ProfileConfig::Root(r) => r.description.as_deref().unwrap_or(""),
                ProfileConfig::Derived(d) => d.description.as_deref().unwrap_or(""),
            };
            if desc_str.is_empty() {
                writeln!(writer, "{marker} {name} [{kind_str}]{default_suffix}")?;
            } else {
                writeln!(
                    writer,
                    "{marker} {name} [{kind_str}]{default_suffix} - {desc_str}"
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONFIG: &str = r#"
version = 1
default_profile = "reader"

[profile.developer]
kind = "root"
description = "Full developer privilege ceiling backed by the Dev GitHub App"
github_app.account = "acme-corp"
github_app.client_id = "Iv1.8888888888888888"
github_app.client_secret = "secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

[profile.reader]
kind = "derived"
source = "developer"
description = "Read-only access to repository contents, pull requests, and issues"
repo = "auto"
permissions = { contents = "read", pull_requests = "read", issues = "read" }
"#;

    #[test]
    fn test_print_profiles_concise() {
        let config: Config = SAMPLE_CONFIG.parse().unwrap();
        let mut buf = Vec::new();
        print_profiles(&mut buf, &config, false).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains(
            "  developer [root] - Full developer privilege ceiling backed by the Dev GitHub App"
        ));
        assert!(output.contains(
            "* reader [derived] (default) - Read-only access to repository contents, pull requests, and issues"
        ));
        assert!(!output.contains("secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
    }

    #[test]
    fn test_print_profiles_verbose() {
        let config: Config = SAMPLE_CONFIG.parse().unwrap();
        let mut buf = Vec::new();
        print_profiles(&mut buf, &config, true).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Configured Profiles:"));
        assert!(output.contains("  developer [root]"));
        assert!(output.contains("    Account:     acme-corp"));
        assert!(output.contains("    Client ID:   Iv1.8888888888888888"));
        assert!(output.contains("* reader [derived] (default)"));
        assert!(output.contains("    Source:      developer"));
        assert!(output.contains("    Repo Scope:  auto"));
        assert!(output.contains("    Permissions: contents=read, issues=read, pull_requests=read"));
        assert!(!output.contains("secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
    }
}
