use crate::cmd::{CmdError, GhstCli, RunCmd, resolve_profile_name};
use crate::github::GitHubClient;
use crate::run::process::OsProcess;
use crate::run::workflow::{CleanupStatus, ExecuteError, RunRequest, execute_run};

pub enum RunOutcome {
    GhstError(CmdError),
    ChildExit(i32),
}

impl From<CmdError> for RunOutcome {
    fn from(error: CmdError) -> Self {
        Self::GhstError(error)
    }
}

pub fn run_run(args: &GhstCli, cmd: &RunCmd) -> RunOutcome {
    match execute(args, cmd) {
        Ok(code) => RunOutcome::ChildExit(code),
        Err(error) => RunOutcome::GhstError(error),
    }
}

fn execute(args: &GhstCli, cmd: &RunCmd) -> Result<i32, CmdError> {
    if cmd.command.is_empty() {
        return Err(CmdError::MissingRunCommand);
    }
    let config = crate::config::load(args.config.as_deref())?;
    let profile_name = resolve_profile_name(cmd.profile.as_deref(), &config)?;
    let profile = config.resolve_token_profile(&profile_name)?;
    let cache_dir = crate::config::cache_dir()?;
    let store = crate::cache::CacheStore::new(&cache_dir);
    let client = GitHubClient::new();
    let process = OsProcess;
    let wrapper_pid = std::process::id();

    tracing::debug!(
        profile = profile_name,
        requested_repositories = ?cmd.repo,
        wrapper_pid,
        "minting a fresh run token"
    );

    let params = prepare_run_parameters(&profile, &cmd.repo, crate::git::resolve_origin_repo)?;

    let request = RunRequest {
        profile_name: &profile_name,
        source_name: params.source_name,
        app: params.app,
        permissions: params.permissions,
        repositories: &params.repositories,
        wrapper_pid,
        command: &cmd.command,
    };

    match execute_run(&client, &store, &process, &process, &request) {
        Ok(execution) => {
            if execution.cleanup.is_incomplete() {
                eprintln!(
                    "Warning: run token cleanup was incomplete; recovery state was retained for `ghst prune`"
                );
            }
            Ok(execution.exit_code.code())
        }
        Err(error) => {
            if error.cleanup_status() == Some(CleanupStatus::Incomplete) {
                eprintln!(
                    "Warning: run token cleanup was incomplete; recovery state was retained for `ghst prune`"
                );
            }
            Err(map_execute_error(error))
        }
    }
}

fn map_execute_error(error: ExecuteError<crate::cache::CacheError, std::io::Error>) -> CmdError {
    match error {
        ExecuteError::InvalidCommand => CmdError::MissingRunCommand,
        ExecuteError::Token(token_err) => CmdError::Token(token_err),
        ExecuteError::PrepareSignals { source, .. }
        | ExecuteError::Spawn { source, .. }
        | ExecuteError::StartForwarding { source, .. } => CmdError::Io(source),
        ExecuteError::Activation { source, .. } => CmdError::Cache(source),
    }
}

struct RunParameters<'a> {
    source_name: &'a str,
    app: crate::profile::AppCredentials<'a>,
    permissions: &'a std::collections::BTreeMap<String, crate::profile::PermissionLevel>,
    repositories: crate::repository::RepositorySelection,
}

fn prepare_run_parameters<'a>(
    profile: &'a crate::profile::ResolvedTokenProfile<'a>,
    cli_repositories: &[String],
    resolve_auto: impl FnMut() -> Result<String, crate::repository::RepositoryError>,
) -> Result<RunParameters<'a>, CmdError> {
    let crate::profile::ResolvedTokenProfile::Scoped {
        source_name,
        app,
        repository_scope,
        permissions,
        ..
    } = profile
    else {
        let name = match profile {
            crate::profile::ResolvedTokenProfile::Base { name, .. }
            | crate::profile::ResolvedTokenProfile::Scoped { name, .. } => (*name).to_owned(),
        };
        return Err(CmdError::RunRequiresScoped(name));
    };
    let repositories = crate::repository::RepositorySelection::resolve(
        cli_repositories,
        repository_scope,
        app.authority.account,
        resolve_auto,
    )?;
    Ok(RunParameters {
        source_name,
        app: *app,
        permissions,
        repositories,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> crate::config::Config {
        r#"
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
        .unwrap()
    }

    #[test]
    fn run_rejects_app_profiles_before_minting() {
        let config = test_config();
        let profile = config.resolve_token_profile("developer").unwrap();
        let result = prepare_run_parameters(&profile, &[], || panic!("auto must not be called"));
        assert!(matches!(
            result,
            Err(CmdError::RunRequiresScoped(name)) if name == "developer"
        ));
    }

    #[test]
    fn run_returns_repository_resolution_failure_before_minting() {
        let config = test_config();
        let profile = config.resolve_token_profile("reader").unwrap();
        let result = prepare_run_parameters(&profile, &["invalid-repo".into()], || {
            panic!("auto must not be called")
        });
        assert!(matches!(
            result,
            Err(CmdError::Repository(
                crate::repository::RepositoryError::InvalidScope { .. }
            ))
        ));
    }

    #[test]
    fn auto_is_not_invoked_for_run_with_explicit_selection() {
        let config = test_config();
        let profile = config.resolve_token_profile("reader").unwrap();
        let params = prepare_run_parameters(&profile, &["acme/other".into()], || {
            panic!("auto must not be called")
        })
        .unwrap();
        assert_eq!(params.source_name, "developer");
        assert_eq!(params.repositories.canonical(), "acme/other");
    }
}
