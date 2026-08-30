use crate::cache::compute_cache_key;
use crate::cmd::{CmdError, GhstCli, OutputFormat, TokenCmd, resolve_profile_name};
use crate::github::GitHubClient;
use crate::repository::RepositoryError;
use crate::token::{AcquireRequest, AcquiredToken, ScopedTokenClient};
use std::io::{self, Write};
use std::path::Path;

/// Handles execution of the `ghst token` subcommand.
pub fn run_token(args: &GhstCli, cmd: &TokenCmd) -> Result<(), CmdError> {
    let config = crate::config::load(args.config.as_deref())?;
    let profile_name = resolve_profile_name(cmd.profile.as_deref(), &config)?;
    let cache_dir = crate::config::cache_dir()?;
    tracing::debug!(
        profile = profile_name,
        requested_repositories = ?cmd.repo,
        output_format = ?cmd.format,
        "acquiring token"
    );
    let client = GitHubClient::new();
    let mut stdout = io::stdout().lock();
    execute_token(
        &TokenContext {
            config: &config,
            cache_dir: &cache_dir,
            client: &client,
        },
        &profile_name,
        cmd,
        &mut stdout,
        crate::git::resolve_origin_repo,
    )
}

struct TokenContext<'a, C> {
    config: &'a crate::config::Config,
    cache_dir: &'a Path,
    client: &'a C,
}

fn execute_token<C: ScopedTokenClient, W: Write>(
    context: &TokenContext<'_, C>,
    profile_name: &str,
    cmd: &TokenCmd,
    writer: &mut W,
    resolve_auto: impl FnMut() -> Result<String, RepositoryError>,
) -> Result<(), CmdError> {
    let token = crate::token::acquire(
        context.client,
        &AcquireRequest {
            config: context.config,
            cache_dir: context.cache_dir,
            profile_name,
            repositories: &cmd.repo,
        },
        resolve_auto,
    )?;
    tracing::debug!(
        profile = token.profile,
        repo_scope = token.repo_scope,
        expires_at = %token.expires_at,
        "token acquired; writing requested output format"
    );
    write_token(writer, &token, cmd.format)?;
    Ok(())
}

fn write_token(
    writer: &mut impl Write,
    token: &AcquiredToken,
    format: OutputFormat,
) -> io::Result<()> {
    match format {
        OutputFormat::Text => writeln!(writer, "{}", token.access_token.as_ref()),
        OutputFormat::Env => {
            let quoted = shell_quote(token.access_token.as_ref());
            writeln!(writer, "export GH_TOKEN={quoted} GITHUB_TOKEN={quoted}")
        }
        OutputFormat::Json => {
            serde_json::to_writer(
                &mut *writer,
                &serde_json::json!({
                    "id": &compute_cache_key(token.profile.as_str(), token.repo_scope.as_str(),)[..crate::cache::MIN_CACHE_ID_LENGTH],
                    "expires_at": token.expires_at.value().unix_timestamp(),
                    "profile": token.profile.as_str(),
                    "repo": token.repo_scope.as_str(),
                    "token": token.access_token.as_ref(),
                }),
            )
            .map_err(|source| {
                io::Error::new(
                    source.io_error_kind().unwrap_or(io::ErrorKind::Other),
                    source,
                )
            })?;
            writer.write_all(b"\n")
        }
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::TokenExpiry;
    use time::{Duration, OffsetDateTime};

    fn token(access_token: &str) -> AcquiredToken {
        AcquiredToken {
            access_token: access_token.into(),
            expires_at: TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(1)),
            profile: "reader".into(),
            repo_scope: "acme/api".into(),
        }
    }

    #[test]
    fn output_formats_remain_exact() {
        let token = token("secret-token");
        let mut text = Vec::new();
        write_token(&mut text, &token, OutputFormat::Text).unwrap();
        assert_eq!(text, b"secret-token\n");

        let mut env = Vec::new();
        write_token(&mut env, &token, OutputFormat::Env).unwrap();
        assert_eq!(
            env,
            b"export GH_TOKEN='secret-token' GITHUB_TOKEN='secret-token'\n"
        );

        let mut json = Vec::new();
        write_token(&mut json, &token, OutputFormat::Json).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(value["token"], "secret-token");
        assert_eq!(
            value["expires_at"],
            token.expires_at.value().unix_timestamp()
        );
        assert_eq!(value["profile"], "reader");
        assert_eq!(value["repo"], "acme/api");
    }

    #[test]
    fn environment_output_quotes_embedded_single_quotes() {
        let mut output = Vec::new();
        write_token(&mut output, &token("a'b"), OutputFormat::Env).unwrap();
        assert_eq!(
            output,
            b"export GH_TOKEN='a'\"'\"'b' GITHUB_TOKEN='a'\"'\"'b'\n"
        );
    }

    #[test]
    fn output_write_failures_are_reported() {
        let error = write_token(
            &mut FailingWriter,
            &token("secret-token"),
            OutputFormat::Json,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "writer failed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
