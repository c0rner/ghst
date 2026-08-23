use crate::cmd::{CmdError, EditCmd, GhstCli};
use crate::config::{self, ConfigLocation};
use std::env;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::{Command, Stdio};

const FALLBACK_EDITORS: [&str; 3] = ["nano", "vim", "vi"];

struct EditorCommand {
    executable: OsString,
    arguments: Vec<OsString>,
}

impl EditorCommand {
    fn name(&self) -> String {
        self.executable.to_string_lossy().into_owned()
    }
}

/// Opens the active configuration, restores its private permissions, and validates it.
///
/// # Errors
///
/// Returns `CmdError` if path resolution, initialization, editor execution, permission
/// enforcement, or configuration validation fails.
pub fn run_edit(args: &GhstCli, cmd: &EditCmd) -> Result<(), CmdError> {
    let location = config::config_location(args.config.as_deref())?;
    let initialized = if cmd.init {
        Some(location.initialize()?)
    } else if location.exists()? {
        None
    } else {
        return Err(CmdError::ConfigNotFound(location.path().to_path_buf()));
    };

    location.enforce_permissions()?;
    match initialized {
        Some(true) => println!("Initialized configuration at {}", location.path().display()),
        Some(false) => println!(
            "Configuration already exists; opening {}",
            location.path().display()
        ),
        None => {}
    }

    let editor = discover_editor(
        env::var_os("VISUAL"),
        env::var_os("EDITOR"),
        env::var_os("PATH").as_deref(),
    )?;
    edit_configuration(&location, &editor)?;
    println!("Configuration is valid.");
    Ok(())
}

fn edit_configuration(location: &ConfigLocation, editor: &EditorCommand) -> Result<(), CmdError> {
    let editor_name = editor.name();
    let status = Command::new(&editor.executable)
        .args(&editor.arguments)
        .arg(location.path())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|source| CmdError::EditorLaunch {
            editor: editor_name.clone(),
            source,
        })?;

    // Repair permissions before inspecting the exit status: a failing editor may still have
    // replaced the file using the process umask.
    location.enforce_permissions()?;
    if !status.success() {
        return Err(CmdError::EditorFailed {
            editor: editor_name,
            code: status.code(),
        });
    }
    location.load()?;
    Ok(())
}

fn discover_editor(
    visual: Option<OsString>,
    editor: Option<OsString>,
    path: Option<&OsStr>,
) -> Result<EditorCommand, CmdError> {
    if let Some(command) = configured_editor(visual, "VISUAL")? {
        return Ok(command);
    }
    if let Some(command) = configured_editor(editor, "EDITOR")? {
        return Ok(command);
    }
    FALLBACK_EDITORS
        .into_iter()
        .find(|candidate| executable_on_path(candidate, path))
        .map(|candidate| EditorCommand {
            executable: candidate.into(),
            arguments: Vec::new(),
        })
        .ok_or(CmdError::NoEditorFound)
}

fn configured_editor(
    value: Option<OsString>,
    variable: &'static str,
) -> Result<Option<EditorCommand>, CmdError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    let Some(value) = value.to_str() else {
        return Ok(Some(EditorCommand {
            executable: value,
            arguments: Vec::new(),
        }));
    };
    let words = split_editor_command(value).ok_or(CmdError::InvalidEditorCommand { variable })?;
    let mut words = words.into_iter();
    let Some(executable) = words.next() else {
        return Ok(None);
    };
    Ok(Some(EditorCommand {
        executable: executable.into(),
        arguments: words.map(OsString::from).collect(),
    }))
}

fn split_editor_command(command: &str) -> Option<Vec<String>> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Quote {
        None,
        Single,
        Double,
    }

    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = Quote::None;
    let mut escaped = false;
    let mut started = false;

    for character in command.chars() {
        if quote != Quote::Single && escaped {
            current.push(character);
            escaped = false;
            started = true;
            continue;
        }
        match (quote, character) {
            (Quote::Single, '\'') | (Quote::Double, '"') => quote = Quote::None,
            (Quote::Single, _) => {
                current.push(character);
                started = true;
            }
            (Quote::None | Quote::Double, '\\') => {
                escaped = true;
                started = true;
            }
            (Quote::None, '\'') => {
                quote = Quote::Single;
                started = true;
            }
            (Quote::None, '"') => {
                quote = Quote::Double;
                started = true;
            }
            (Quote::None, character) if character.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            (_, character) => {
                current.push(character);
                started = true;
            }
        }
    }
    if escaped || quote != Quote::None {
        return None;
    }
    if started {
        words.push(current);
    }
    Some(words)
}

fn executable_on_path(executable: &str, path: Option<&OsStr>) -> bool {
    let Some(path) = path else {
        return false;
    };
    env::split_paths(path).any(|directory| is_executable(&directory.join(executable)))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_without_init_reports_missing_configuration() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("missing.toml");
        let args = GhstCli {
            config: Some(path.clone()),
            command: crate::cmd::SubCommand::Edit(EditCmd { init: false }),
        };

        assert!(matches!(
            run_edit(&args, &EditCmd { init: false }),
            Err(CmdError::ConfigNotFound(error_path)) if error_path == path
        ));
    }

    #[test]
    fn configured_editor_supports_arguments_and_quotes() {
        let editor = configured_editor(Some("code --wait 'profile file'".into()), "VISUAL")
            .unwrap()
            .unwrap();
        assert_eq!(editor.executable, OsString::from("code"));
        assert_eq!(
            editor.arguments,
            [OsString::from("--wait"), OsString::from("profile file")]
        );
        assert!(matches!(
            configured_editor(Some("code 'unterminated".into()), "EDITOR"),
            Err(CmdError::InvalidEditorCommand { variable: "EDITOR" })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn editor_discovery_prefers_visual_then_editor_then_path() {
        use std::os::unix::fs::PermissionsExt;

        let selected = discover_editor(
            Some("visual-editor --wait".into()),
            Some("other-editor".into()),
            None,
        )
        .unwrap();
        assert_eq!(selected.executable, OsString::from("visual-editor"));

        let temp = tempfile::tempdir().unwrap();
        let fallback = temp.path().join("vim");
        std::fs::write(&fallback, "").unwrap();
        std::fs::set_permissions(&fallback, std::fs::Permissions::from_mode(0o700)).unwrap();
        let search_path = env::join_paths([temp.path()]).unwrap();
        let selected = discover_editor(Some("  ".into()), None, Some(&search_path)).unwrap();
        assert_eq!(selected.executable, OsString::from("vim"));
    }

    #[cfg(unix)]
    #[test]
    fn failing_editor_still_has_its_permission_changes_repaired() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("profiles.toml");
        std::fs::write(&path, config::STARTER_TEMPLATE).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let location = config::config_location(Some(&path)).unwrap();
        let editor = EditorCommand {
            executable: "/bin/sh".into(),
            arguments: [
                "-c",
                "printf 'version = 1\\n' > \"$1.tmp\"; chmod 644 \"$1.tmp\"; mv \"$1.tmp\" \"$1\"; exit 7",
                "ghst-test",
            ]
            .map(OsString::from)
            .into(),
        };

        assert!(matches!(
            edit_configuration(&location, &editor),
            Err(CmdError::EditorFailed { code: Some(7), .. })
        ));
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn successful_editor_is_followed_by_schema_validation() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("profiles.toml");
        std::fs::write(&path, config::STARTER_TEMPLATE).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let location = config::config_location(Some(&path)).unwrap();
        let editor = EditorCommand {
            executable: "/bin/sh".into(),
            arguments: ["-c", "printf 'version = 2\\n' > \"$1\"", "ghst-test"]
                .map(OsString::from)
                .into(),
        };

        assert!(matches!(
            edit_configuration(&location, &editor),
            Err(CmdError::Config(config::ConfigError::UnsupportedVersion(2)))
        ));
    }
}
