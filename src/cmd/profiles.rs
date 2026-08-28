use crate::cmd::{CmdError, GhstCli, ProfilesCmd};
use crate::config::{Config, ProfileConfig};
use std::io::{self, Write};

/// Handles execution of the `ghst profiles` subcommand.
///
/// # Errors
///
/// Returns `CmdError` if loading configuration or printing profiles fails.
pub fn run_profiles(args: &GhstCli, cmd: &ProfilesCmd) -> Result<(), CmdError> {
    let config = crate::config::load(args.config.as_deref())?;
    tracing::debug!(
        profiles = config.profiles.len(),
        verbose = cmd.verbose,
        "listing configured profiles"
    );

    print_profiles(&mut io::stdout(), &config, cmd.verbose)?;
    Ok(())
}

fn print_profiles<W: Write>(writer: &mut W, config: &Config, verbose: bool) -> io::Result<()> {
    if verbose {
        writeln!(writer, "Configured Profiles:\n")?;
    }

    for (name, profile) in &config.profiles {
        let is_default = config.default_profile.as_deref() == Some(name.as_str());
        let marker = if is_default { "*" } else { " " };
        let default_suffix = if is_default { " (default)" } else { "" };
        let kind = profile.kind_name();

        if verbose {
            writeln!(writer, "{marker} {name} [{kind}]{default_suffix}")?;
            match profile {
                ProfileConfig::App(app) => {
                    writeln!(writer, "    Account:     {}", app.github_app.account)?;
                    writeln!(writer, "    Repo Scope:  all (app authority)")?;
                    let capabilities = if app.github_app.client_secret.is_some() {
                        "base tokens, scoped tokens, remote revocation"
                    } else {
                        "base tokens only"
                    };
                    writeln!(writer, "    Capabilities: {capabilities}")?;
                }
                ProfileConfig::Scoped(scoped) => {
                    writeln!(writer, "    Source:      {}", scoped.source)?;
                    writeln!(writer, "    Repo Scope:  {}", scoped.repo)?;
                    if !scoped.permissions.is_empty() {
                        let perms = scoped
                            .permissions
                            .iter()
                            .map(|(k, v)| format!("{k}={v}"))
                            .collect::<Vec<_>>()
                            .join(", ");
                        writeln!(writer, "    Permissions: {perms}")?;
                    }
                }
            }
            if let Some(desc) = profile.description() {
                writeln!(writer, "    Description: {desc}")?;
            }
            writeln!(writer)?;
        } else if let Some(desc) = profile.description() {
            writeln!(writer, "{marker} {name} [{kind}]{default_suffix} - {desc}")?;
        } else {
            writeln!(writer, "{marker} {name} [{kind}]{default_suffix}")?;
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
description = "Full developer privilege ceiling backed by the Dev GitHub App"
github_app.account = "acme-corp"
github_app.client_id = "Iv1.8888888888888888"
github_app.client_secret = "secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

[profile.reader]
source = "developer"
description = "Read-only access to repository contents, pull requests, and issues"
repo = ["acme-corp/application", "acme-corp/shared-library", "auto"]
permissions = { contents = "read", pull_requests = "read", issues = "read" }
"#;

    #[test]
    fn test_print_profiles_concise() {
        let config: Config = SAMPLE_CONFIG.parse().unwrap();
        let mut buf = Vec::new();
        print_profiles(&mut buf, &config, false).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains(
            "  developer [app] - Full developer privilege ceiling backed by the Dev GitHub App"
        ));
        assert!(output.contains(
            "* reader [scoped] (default) - Read-only access to repository contents, pull requests, and issues"
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
        assert!(output.contains("  developer [app]"));
        assert!(output.contains("    Account:     acme-corp"));
        assert!(!output.contains("Iv1.8888888888888888"));
        assert!(output.contains("    Repo Scope:  all (app authority)"));
        assert!(output.contains("    Capabilities: base tokens, scoped tokens, remote revocation"));
        assert!(output.contains("* reader [scoped] (default)"));
        assert!(output.contains("    Source:      developer"));
        assert!(
            output.contains(
                "    Repo Scope:  [acme-corp/application, acme-corp/shared-library, auto]"
            )
        );
        assert!(output.contains("    Permissions: contents=read, issues=read, pull_requests=read"));
        assert!(!output.contains("secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
    }
}
