use crate::cache::{
    AccessToken, CACHE_SCHEMA_VERSION, CacheEntry, CacheKind, DerivedCacheEntry, LegacyCacheEntry,
    SaveCacheEntry, TokenExpiry, compute_cache_key, format_rfc3339, load_cache_entry,
    policy_fingerprint, save_cache_entry,
};
use crate::cmd::{
    CmdError, GhstCli, OutputFormat, RepositorySelection, TokenCmd, load_config,
    load_current_root_entry, load_valid_root_entry, resolve_profile_name, revoke_with_context,
};
use crate::config::{Config, DerivedProfile, ProfileConfig, RootProfile};
use crate::github::{GitHubClient, ScopedTokenClient, ScopedTokenResponse};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use time::OffsetDateTime;
use tracing::info;

const MAX_SCOPED_LIFETIME: time::Duration = time::Duration::hours(8);
const SCOPED_EXPIRY_ROUNDING_TOLERANCE: time::Duration = time::Duration::seconds(1);

/// Handles execution of the `ghst token` subcommand.
///
/// # Errors
///
/// Returns `CmdError` if request resolution, cache validation, token minting,
/// persistence, cleanup, or output fails.
pub fn run_token(args: &GhstCli, cmd: &TokenCmd) -> Result<(), CmdError> {
    info!(
        "Command: token (profile: {:?}, repo: {:?}, format: {:?})",
        cmd.profile, cmd.repo, cmd.format
    );
    let config = load_config(args.config.as_deref())?;
    let profile_name = resolve_profile_name(cmd.profile.as_deref(), &config)?;
    let cache_dir = Config::cache_dir()?;
    let client = GitHubClient::new();
    let mut stdout = io::stdout().lock();
    let context = TokenContext {
        config: &config,
        cache_dir: &cache_dir,
        client: &client,
        now: OffsetDateTime::now_utc(),
    };
    execute_token(
        &context,
        &profile_name,
        cmd,
        &mut stdout,
        crate::git::resolve_origin_repo,
    )
}

struct TokenContext<'a, C> {
    config: &'a Config,
    cache_dir: &'a Path,
    client: &'a C,
    now: OffsetDateTime,
}

fn execute_token<C: ScopedTokenClient, W: Write>(
    context: &TokenContext<'_, C>,
    profile_name: &str,
    cmd: &TokenCmd,
    writer: &mut W,
    resolve_auto: impl FnMut() -> Result<String, crate::git::GitError>,
) -> Result<(), CmdError> {
    let profile = context
        .config
        .profiles
        .get(profile_name)
        .ok_or_else(|| CmdError::ProfileNotFound(profile_name.to_owned()))?;
    match profile {
        ProfileConfig::Root(root) => handle_root(context, profile_name, root, cmd, writer),
        ProfileConfig::Derived(derived) => {
            handle_derived(context, profile_name, derived, cmd, writer, resolve_auto)
        }
    }
}

fn handle_root<C: ScopedTokenClient, W: Write>(
    context: &TokenContext<'_, C>,
    profile_name: &str,
    profile: &RootProfile,
    cmd: &TokenCmd,
    writer: &mut W,
) -> Result<(), CmdError> {
    if !cmd.repo.is_empty() {
        return Err(CmdError::RootScopeRejected {
            profile: profile_name.to_owned(),
        });
    }
    let entry = load_valid_root_entry(context.cache_dir, profile_name, profile, context.now)?
        .ok_or_else(|| CmdError::NoRootTokenCached {
            profile: profile_name.to_owned(),
        })?;
    write_token(
        writer,
        &entry.access_token,
        entry.expires_at,
        profile_name,
        "all",
        cmd.format,
    )?;
    Ok(())
}

fn handle_derived<C: ScopedTokenClient, W: Write>(
    context: &TokenContext<'_, C>,
    profile_name: &str,
    profile: &DerivedProfile,
    cmd: &TokenCmd,
    writer: &mut W,
    resolve_auto: impl FnMut() -> Result<String, crate::git::GitError>,
) -> Result<(), CmdError> {
    let selection = RepositorySelection::resolve(&cmd.repo, &profile.repo, resolve_auto)?;
    let canonical_scope = selection.canonical();
    let source_name = &profile.source;
    let source_profile = resolve_source_profile(context.config, profile_name, source_name)?;
    let repositories = selection.repository_names(&source_profile.github_app.account)?;
    let permissions = permission_request(&profile.permissions);
    let policy = policy_fingerprint(
        &source_profile.github_app.account,
        &canonical_scope,
        &permissions,
    );

    let root_entry = load_current_root_entry(context.cache_dir, source_name, source_profile)?
        .ok_or_else(|| CmdError::NoSourceTokenCached {
            profile: source_name.clone(),
        })?;
    let parent_generation = root_entry.generation_fingerprint();
    let cache_key = compute_cache_key(profile_name, &canonical_scope);

    let provenance = DerivedProvenance {
        profile_name,
        source_name,
        canonical_scope: &canonical_scope,
        policy: &policy,
        parent_generation: &parent_generation,
    };
    if let Some(entry) =
        load_valid_derived_entry(context.cache_dir, &cache_key, &provenance, context.now)?
    {
        write_token(
            writer,
            &entry.access_token,
            entry.expires_at,
            profile_name,
            &canonical_scope,
            cmd.format,
        )?;
        return Ok(());
    }

    if !root_entry.expires_at.is_usable_at(context.now) {
        return Err(CmdError::NoSourceTokenCached {
            profile: source_name.clone(),
        });
    }

    let request = MintRequest {
        cache_key: &cache_key,
        profile_name,
        source_name,
        source_profile,
        canonical_scope: &canonical_scope,
        repositories: repositories.as_deref(),
        permissions: &permissions,
        policy: &policy,
        root_entry,
        format: cmd.format,
    };
    mint_and_persist(context, request, writer)
}

fn resolve_source_profile<'a>(
    config: &'a Config,
    profile_name: &str,
    source_name: &str,
) -> Result<&'a RootProfile, CmdError> {
    match config.profiles.get(source_name) {
        Some(ProfileConfig::Root(root)) => Ok(root),
        Some(ProfileConfig::Derived(_)) => Err(CmdError::SourceProfileNotRoot {
            profile: profile_name.to_owned(),
            source: source_name.to_owned(),
        }),
        None => Err(CmdError::ProfileNotFound(source_name.to_owned())),
    }
}

fn permission_request(
    permissions: &BTreeMap<String, crate::config::PermissionLevel>,
) -> BTreeMap<String, String> {
    permissions
        .iter()
        .map(|(name, level)| (name.clone(), level.to_string()))
        .collect()
}

struct DerivedProvenance<'a> {
    profile_name: &'a str,
    source_name: &'a str,
    canonical_scope: &'a str,
    policy: &'a str,
    parent_generation: &'a str,
}

fn load_valid_derived_entry(
    cache_dir: &Path,
    cache_key: &str,
    provenance: &DerivedProvenance<'_>,
    now: OffsetDateTime,
) -> Result<Option<DerivedCacheEntry>, CmdError> {
    let Some(entry) = load_cache_entry(cache_dir, cache_key)? else {
        return Ok(None);
    };
    if entry.profile() != provenance.profile_name {
        return Err(CmdError::InconsistentCacheMetadata {
            profile: provenance.profile_name.to_owned(),
            found: entry.profile().to_owned(),
        });
    }
    match entry {
        CacheEntry::Derived(entry) => {
            let valid = entry.version == CACHE_SCHEMA_VERSION
                && entry.source_profile == provenance.source_name
                && entry.repo_scope == provenance.canonical_scope
                && entry.policy_fingerprint == provenance.policy
                && entry.parent_generation == provenance.parent_generation
                && entry.expires_at.is_usable_at(now);
            Ok(valid.then_some(entry))
        }
        CacheEntry::Legacy(LegacyCacheEntry::Derived(_)) => Ok(None),
        CacheEntry::Root(_) | CacheEntry::Legacy(LegacyCacheEntry::Root(_)) => {
            Err(CmdError::UnexpectedCacheKind {
                profile: provenance.profile_name.to_owned(),
                expected: CacheKind::Derived,
                actual: CacheKind::Root,
            })
        }
    }
}

struct MintRequest<'a> {
    cache_key: &'a str,
    profile_name: &'a str,
    source_name: &'a str,
    source_profile: &'a RootProfile,
    canonical_scope: &'a str,
    repositories: Option<&'a [String]>,
    permissions: &'a BTreeMap<String, String>,
    policy: &'a str,
    root_entry: crate::cache::RootCacheEntry,
    format: OutputFormat,
}

fn mint_and_persist<C: ScopedTokenClient, W: Write>(
    context: &TokenContext<'_, C>,
    request: MintRequest<'_>,
    writer: &mut W,
) -> Result<(), CmdError> {
    let MintRequest {
        cache_key,
        profile_name,
        source_name,
        source_profile,
        canonical_scope,
        repositories,
        permissions,
        policy,
        root_entry,
        format,
    } = request;
    let response = context.client.create_scoped_token(
        &source_profile.github_app.client_id,
        &source_profile.github_app.client_secret,
        root_entry.access_token.as_ref(),
        &source_profile.github_app.account,
        repositories,
        permissions,
    )?;
    let ScopedTokenResponse {
        token, expires_at, ..
    } = response;
    let response_received_at = OffsetDateTime::now_utc();

    let expiry = match validate_scoped_expiry(expires_at.as_deref(), response_received_at) {
        Ok(expiry) => expiry,
        Err(error) => {
            return Err(revoke_with_context(
                context.client,
                source_profile,
                &token,
                error,
            ));
        }
    };

    ensure_root_generation(
        context,
        source_name,
        source_profile,
        &token,
        &root_entry.generation_fingerprint(),
    )?;

    let candidate = CacheEntry::Derived(DerivedCacheEntry {
        version: CACHE_SCHEMA_VERSION,
        profile: profile_name.to_owned(),
        source_profile: source_name.to_owned(),
        parent_generation: root_entry.generation_fingerprint(),
        policy_fingerprint: policy.to_owned(),
        github_user: root_entry.github_user,
        repo_scope: canonical_scope.to_owned(),
        issued_at: format_rfc3339(response_received_at),
        expires_at: expiry,
        access_token: token,
    });

    let persistence = PersistenceRequest {
        cache_key,
        profile_name,
        source_profile,
        format,
    };
    persist_scoped_candidate(context, &persistence, &candidate, writer)
}

fn ensure_root_generation<C: ScopedTokenClient>(
    context: &TokenContext<'_, C>,
    source_name: &str,
    source_profile: &RootProfile,
    token: &AccessToken,
    expected_generation: &str,
) -> Result<(), CmdError> {
    let reread = load_current_root_entry(context.cache_dir, source_name, source_profile);
    match reread {
        Ok(Some(current)) if current.generation_fingerprint() == expected_generation => Ok(()),
        Ok(Some(_) | None) => Err(revoke_with_context(
            context.client,
            source_profile,
            token,
            CmdError::RootGenerationChanged {
                profile: source_name.to_owned(),
            },
        )),
        Err(error) => Err(revoke_with_context(
            context.client,
            source_profile,
            token,
            error,
        )),
    }
}

struct PersistenceRequest<'a> {
    cache_key: &'a str,
    profile_name: &'a str,
    source_profile: &'a RootProfile,
    format: OutputFormat,
}

fn persist_scoped_candidate<C: ScopedTokenClient, W: Write>(
    context: &TokenContext<'_, C>,
    request: &PersistenceRequest<'_>,
    candidate: &CacheEntry,
    writer: &mut W,
) -> Result<(), CmdError> {
    let save_result = match save_cache_entry(context.cache_dir, request.cache_key, candidate) {
        Ok(result) => result,
        Err(error) => {
            let token = derived_token(candidate)?;
            return Err(revoke_with_context(
                context.client,
                request.source_profile,
                token,
                CmdError::Cache(error),
            ));
        }
    };

    match save_result {
        SaveCacheEntry::Saved => output_derived(writer, candidate, request.format),
        SaveCacheEntry::Retained(retained) => {
            let candidate_token = derived_token(candidate)?;
            if let Err(source) = context.client.delete_token(
                &request.source_profile.github_app.client_id,
                &request.source_profile.github_app.client_secret,
                candidate_token.as_ref(),
            ) {
                return Err(CmdError::RevocationFailed {
                    context: Box::new(CmdError::StaleProvenance {
                        profile: request.profile_name.to_owned(),
                        reason: "a compatible concurrent cache winner retained the token",
                    }),
                    source,
                });
            }
            output_derived(writer, &retained, request.format)
        }
    }
}

fn validate_scoped_expiry(
    value: Option<&str>,
    now: OffsetDateTime,
) -> Result<TokenExpiry, CmdError> {
    let value = value.ok_or_else(|| CmdError::InvalidLifetime {
        token_kind: "scoped",
        reason: "response did not contain expires_at".into(),
    })?;
    let expiry = TokenExpiry::parse(value).map_err(|_| CmdError::InvalidLifetime {
        token_kind: "scoped",
        reason: "expires_at is not valid RFC 3339".into(),
    })?;
    if !expiry.is_usable_at(now) {
        return Err(CmdError::InvalidLifetime {
            token_kind: "scoped",
            reason: "expires_at is not beyond the 30-second safety margin".into(),
        });
    }
    if expiry.value() > now + MAX_SCOPED_LIFETIME + SCOPED_EXPIRY_ROUNDING_TOLERANCE {
        return Err(CmdError::InvalidLifetime {
            token_kind: "scoped",
            reason: "expires_at exceeds the supported eight-hour maximum and one-second timestamp rounding tolerance".into(),
        });
    }
    Ok(expiry)
}

fn derived_entry(entry: &CacheEntry) -> Result<&DerivedCacheEntry, CmdError> {
    entry
        .as_derived()
        .ok_or_else(|| CmdError::UnexpectedCacheKind {
            profile: entry.profile().to_owned(),
            expected: CacheKind::Derived,
            actual: entry.kind(),
        })
}

fn derived_token(entry: &CacheEntry) -> Result<&AccessToken, CmdError> {
    derived_entry(entry).map(|derived| &derived.access_token)
}

fn output_derived<W: Write>(
    writer: &mut W,
    entry: &CacheEntry,
    format: OutputFormat,
) -> Result<(), CmdError> {
    let entry = derived_entry(entry)?;
    write_token(
        writer,
        &entry.access_token,
        entry.expires_at,
        &entry.profile,
        &entry.repo_scope,
        format,
    )?;
    Ok(())
}

fn write_token<W: Write>(
    writer: &mut W,
    access_token: &AccessToken,
    expires_at: TokenExpiry,
    profile_name: &str,
    repo_scope: &str,
    format: OutputFormat,
) -> io::Result<()> {
    match format {
        OutputFormat::Text => writeln!(writer, "{}", access_token.as_ref()),
        OutputFormat::Env => writeln!(
            writer,
            "export GITHUB_TOKEN={}",
            shell_quote(access_token.as_ref())
        ),
        OutputFormat::Json => {
            serde_json::to_writer(
                &mut *writer,
                &serde_json::json!({
                    "token": access_token.as_ref(),
                    "expires_at": expires_at.to_string(),
                    "profile": profile_name,
                    "repo": repo_scope,
                }),
            )
            .map_err(io::Error::other)?;
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
    use crate::cache::{
        RootCacheEntry, authority_fingerprint, delete_cache_entry, save_cache_entry,
    };
    use crate::cmd::root_cache_key;
    use crate::github::{GitHubError, RevokeTokenClient, ScopedTokenResponse};
    use std::cell::RefCell;
    use time::Duration;

    const CONFIG: &str = r#"
version = 1
default_profile = "reader"

[profile.developer]
kind = "root"
github_app.account = "acme"
github_app.client_id = "id"
github_app.client_secret = "secret"

[profile.reader]
kind = "derived"
source = "developer"
repo = "acme/api"
permissions = { contents = "read", pull_requests = "write" }
"#;

    struct MockClient {
        response: RefCell<Option<Result<ScopedTokenResponse, GitHubError>>>,
        request: RefCell<Option<serde_json::Value>>,
        revoked: RefCell<Vec<String>>,
        revoke_error: bool,
    }

    impl RevokeTokenClient for MockClient {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            access_token: &str,
        ) -> Result<(), GitHubError> {
            self.revoked.borrow_mut().push(access_token.to_owned());
            if self.revoke_error {
                Err(GitHubError::Http {
                    status: 500,
                    message: "revoke failed".into(),
                })
            } else {
                Ok(())
            }
        }
    }

    impl ScopedTokenClient for MockClient {
        fn create_scoped_token(
            &self,
            client_id: &str,
            client_secret: &str,
            root_token: &str,
            target: &str,
            repositories: Option<&[String]>,
            permissions: &BTreeMap<String, String>,
        ) -> Result<ScopedTokenResponse, GitHubError> {
            self.request.replace(Some(serde_json::json!({
                "client_id": client_id,
                "client_secret": client_secret,
                "access_token": root_token,
                "target": target,
                "repositories": repositories,
                "permissions": permissions,
            })));
            self.response.borrow_mut().take().unwrap()
        }
    }

    fn client(response: ScopedTokenResponse) -> MockClient {
        MockClient {
            response: RefCell::new(Some(Ok(response))),
            request: RefCell::new(None),
            revoked: RefCell::new(Vec::new()),
            revoke_error: false,
        }
    }

    fn cache_root(cache_dir: &Path, now: OffsetDateTime) {
        let entry = CacheEntry::Root(RootCacheEntry {
            version: CACHE_SCHEMA_VERSION,
            profile: "developer".into(),
            authority_fingerprint: authority_fingerprint("id", "acme"),
            github_user: "octocat".into(),
            issued_at: format_rfc3339(now),
            expires_at: TokenExpiry::new(now + Duration::hours(2)),
            access_token: "root-token".into(),
        });
        save_cache_entry(cache_dir, &root_cache_key("developer"), &entry).unwrap();
    }

    fn command(format: OutputFormat) -> TokenCmd {
        TokenCmd {
            profile: Some("reader".into()),
            repo: Vec::new(),
            format,
        }
    }

    #[test]
    fn scoped_success_sends_exact_request_and_outputs_token() {
        let now = OffsetDateTime::now_utc();
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_root(&cache_dir, now);
        let expiry = TokenExpiry::new(now + Duration::hours(6)).to_string();
        let client = client(ScopedTokenResponse {
            token: "child-token".into(),
            expires_at: Some(expiry.clone()),
            permissions: None,
            repositories: None,
        });
        let config: Config = CONFIG.parse().unwrap();
        let mut output = Vec::new();
        let context = TokenContext {
            config: &config,
            cache_dir: &cache_dir,
            client: &client,
            now,
        };

        execute_token(
            &context,
            "reader",
            &command(OutputFormat::Json),
            &mut output,
            || panic!("auto not expected"),
        )
        .unwrap();

        assert_eq!(
            client.request.borrow().as_ref().unwrap(),
            &serde_json::json!({
                "client_id": "id",
                "client_secret": "secret",
                "access_token": "root-token",
                "target": "acme",
                "repositories": ["api"],
                "permissions": {"contents": "read", "pull_requests": "write"},
            })
        );
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!(
                "{{\"expires_at\":\"{expiry}\",\"profile\":\"reader\",\"repo\":\"acme/api\",\"token\":\"child-token\"}}\n"
            )
        );
    }

    #[test]
    fn invalid_child_expiry_is_revoked_and_not_cached() {
        let now = OffsetDateTime::now_utc();
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_root(&cache_dir, now);
        let client = client(ScopedTokenResponse {
            token: "bad-child".into(),
            expires_at: None,
            permissions: None,
            repositories: None,
        });
        let config: Config = CONFIG.parse().unwrap();
        let context = TokenContext {
            config: &config,
            cache_dir: &cache_dir,
            client: &client,
            now,
        };
        let error = execute_token(
            &context,
            "reader",
            &command(OutputFormat::Text),
            &mut Vec::new(),
            || panic!("auto not expected"),
        )
        .unwrap_err();
        assert!(matches!(error, CmdError::InvalidLifetime { .. }));
        assert_eq!(&*client.revoked.borrow(), &["bad-child"]);
        assert!(
            load_cache_entry(&cache_dir, &compute_cache_key("reader", "acme/api"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn scoped_expiry_validates_lifetime_with_timestamp_rounding_tolerance() {
        let now = OffsetDateTime::now_utc();
        for value in [
            Some("not-a-timestamp".to_owned()),
            Some(TokenExpiry::new(now + Duration::seconds(30)).to_string()),
            Some(TokenExpiry::new(now + Duration::hours(8) + Duration::seconds(2)).to_string()),
        ] {
            assert!(matches!(
                validate_scoped_expiry(value.as_deref(), now),
                Err(CmdError::InvalidLifetime { .. })
            ));
        }

        let issued_at = OffsetDateTime::parse(
            "2026-08-01T17:20:25.889841154Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let github_expiry = "2026-08-02T01:20:26.000Z";
        assert_eq!(
            validate_scoped_expiry(Some(github_expiry), issued_at)
                .unwrap()
                .value(),
            TokenExpiry::parse(github_expiry).unwrap().value()
        );
    }

    struct WinningClient<'a> {
        cache_dir: &'a Path,
        now: OffsetDateTime,
        parent_generation: String,
        policy: String,
        revoked: RefCell<Vec<String>>,
    }

    impl RevokeTokenClient for WinningClient<'_> {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            access_token: &str,
        ) -> Result<(), GitHubError> {
            self.revoked.borrow_mut().push(access_token.to_owned());
            Ok(())
        }
    }

    impl ScopedTokenClient for WinningClient<'_> {
        fn create_scoped_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            _root_token: &str,
            _target: &str,
            _repositories: Option<&[String]>,
            _permissions: &BTreeMap<String, String>,
        ) -> Result<ScopedTokenResponse, GitHubError> {
            let winner = CacheEntry::Derived(DerivedCacheEntry {
                version: CACHE_SCHEMA_VERSION,
                profile: "reader".into(),
                source_profile: "developer".into(),
                parent_generation: self.parent_generation.clone(),
                policy_fingerprint: self.policy.clone(),
                github_user: "octocat".into(),
                repo_scope: "acme/api".into(),
                issued_at: format_rfc3339(self.now),
                expires_at: TokenExpiry::new(self.now + Duration::minutes(50)),
                access_token: "winning-token".into(),
            });
            save_cache_entry(
                self.cache_dir,
                &compute_cache_key("reader", "acme/api"),
                &winner,
            )
            .unwrap();
            Ok(ScopedTokenResponse {
                token: "unused-candidate".into(),
                expires_at: Some(TokenExpiry::new(self.now + Duration::minutes(45)).to_string()),
                permissions: None,
                repositories: None,
            })
        }
    }

    #[test]
    fn concurrent_compatible_winner_is_output_and_candidate_is_revoked() {
        let now = OffsetDateTime::now_utc();
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_root(&cache_dir, now);
        let root = load_cache_entry(&cache_dir, &root_cache_key("developer"))
            .unwrap()
            .unwrap();
        let CacheEntry::Root(root) = root else {
            panic!("expected root entry");
        };
        let permissions = BTreeMap::from([
            ("contents".into(), "read".into()),
            ("pull_requests".into(), "write".into()),
        ]);
        let client = WinningClient {
            cache_dir: &cache_dir,
            now,
            parent_generation: root.generation_fingerprint(),
            policy: policy_fingerprint("acme", "acme/api", &permissions),
            revoked: RefCell::new(Vec::new()),
        };
        let config: Config = CONFIG.parse().unwrap();
        let context = TokenContext {
            config: &config,
            cache_dir: &cache_dir,
            client: &client,
            now,
        };
        let mut output = Vec::new();
        execute_token(
            &context,
            "reader",
            &command(OutputFormat::Text),
            &mut output,
            || panic!("auto not expected"),
        )
        .unwrap();
        assert_eq!(output, b"winning-token\n");
        assert_eq!(&*client.revoked.borrow(), &["unused-candidate"]);
    }

    struct GenerationChangingClient<'a> {
        cache_dir: &'a Path,
        now: OffsetDateTime,
        revoked: RefCell<Vec<String>>,
    }

    impl RevokeTokenClient for GenerationChangingClient<'_> {
        fn delete_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            access_token: &str,
        ) -> Result<(), GitHubError> {
            self.revoked.borrow_mut().push(access_token.to_owned());
            Ok(())
        }
    }

    impl ScopedTokenClient for GenerationChangingClient<'_> {
        fn create_scoped_token(
            &self,
            _client_id: &str,
            _client_secret: &str,
            _root_token: &str,
            _target: &str,
            _repositories: Option<&[String]>,
            _permissions: &BTreeMap<String, String>,
        ) -> Result<ScopedTokenResponse, GitHubError> {
            let key = root_cache_key("developer");
            delete_cache_entry(self.cache_dir, &key).unwrap();
            let replacement = CacheEntry::Root(RootCacheEntry {
                version: CACHE_SCHEMA_VERSION,
                profile: "developer".into(),
                authority_fingerprint: authority_fingerprint("id", "acme"),
                github_user: "octocat".into(),
                issued_at: format_rfc3339(self.now),
                expires_at: TokenExpiry::new(self.now + Duration::hours(2)),
                access_token: "replacement-root".into(),
            });
            save_cache_entry(self.cache_dir, &key, &replacement).unwrap();
            Ok(ScopedTokenResponse {
                token: "orphaned-child".into(),
                expires_at: Some(TokenExpiry::new(self.now + Duration::minutes(45)).to_string()),
                permissions: None,
                repositories: None,
            })
        }
    }

    #[test]
    fn root_generation_change_after_http_revokes_child_and_requests_retry() {
        let now = OffsetDateTime::now_utc();
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_root(&cache_dir, now);
        let config: Config = CONFIG.parse().unwrap();
        let client = GenerationChangingClient {
            cache_dir: &cache_dir,
            now,
            revoked: RefCell::new(Vec::new()),
        };
        let context = TokenContext {
            config: &config,
            cache_dir: &cache_dir,
            client: &client,
            now,
        };
        let error = execute_token(
            &context,
            "reader",
            &command(OutputFormat::Text),
            &mut Vec::new(),
            || panic!("auto not expected"),
        )
        .unwrap_err();
        assert!(matches!(error, CmdError::RootGenerationChanged { .. }));
        assert_eq!(&*client.revoked.borrow(), &["orphaned-child"]);
    }

    #[test]
    fn root_rejects_any_cli_repository() {
        let config: Config = CONFIG.parse().unwrap();
        let cmd = TokenCmd {
            profile: Some("developer".into()),
            repo: vec!["all".into()],
            format: OutputFormat::Text,
        };
        let client = client(ScopedTokenResponse {
            token: "unused".into(),
            expires_at: None,
            permissions: None,
            repositories: None,
        });
        let now = OffsetDateTime::now_utc();
        let context = TokenContext {
            config: &config,
            cache_dir: Path::new("unused"),
            client: &client,
            now,
        };
        let error = execute_token(&context, "developer", &cmd, &mut Vec::new(), || {
            panic!("auto not expected")
        })
        .unwrap_err();
        assert!(matches!(error, CmdError::RootScopeRejected { .. }));
    }

    #[test]
    fn root_without_repository_outputs_raw_cached_token() {
        let now = OffsetDateTime::now_utc();
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_root(&cache_dir, now);
        let config: Config = CONFIG.parse().unwrap();
        let client = client(ScopedTokenResponse {
            token: "unused".into(),
            expires_at: None,
            permissions: None,
            repositories: None,
        });
        let context = TokenContext {
            config: &config,
            cache_dir: &cache_dir,
            client: &client,
            now,
        };
        let cmd = TokenCmd {
            profile: Some("developer".into()),
            repo: Vec::new(),
            format: OutputFormat::Text,
        };
        let mut output = Vec::new();
        execute_token(&context, "developer", &cmd, &mut output, || {
            panic!("auto not expected")
        })
        .unwrap();
        assert_eq!(output, b"root-token\n");
        assert!(client.request.borrow().is_none());
    }

    #[test]
    fn independently_live_child_is_returned_after_root_expiry() {
        let issued_at = OffsetDateTime::now_utc();
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        cache_root(&cache_dir, issued_at);
        let root = load_cache_entry(&cache_dir, &root_cache_key("developer"))
            .unwrap()
            .unwrap();
        let CacheEntry::Root(root) = root else {
            panic!("expected root entry");
        };
        let permissions = BTreeMap::from([
            ("contents".into(), "read".into()),
            ("pull_requests".into(), "write".into()),
        ]);
        let child = CacheEntry::Derived(DerivedCacheEntry {
            version: CACHE_SCHEMA_VERSION,
            profile: "reader".into(),
            source_profile: "developer".into(),
            parent_generation: root.generation_fingerprint(),
            policy_fingerprint: policy_fingerprint("acme", "acme/api", &permissions),
            github_user: "octocat".into(),
            repo_scope: "acme/api".into(),
            issued_at: format_rfc3339(issued_at),
            expires_at: TokenExpiry::new(issued_at + Duration::hours(6)),
            access_token: "still-live-child".into(),
        });
        save_cache_entry(&cache_dir, &compute_cache_key("reader", "acme/api"), &child).unwrap();

        let config: Config = CONFIG.parse().unwrap();
        let client = client(ScopedTokenResponse {
            token: "must-not-mint".into(),
            expires_at: None,
            permissions: None,
            repositories: None,
        });
        let context = TokenContext {
            config: &config,
            cache_dir: &cache_dir,
            client: &client,
            now: issued_at + Duration::hours(3),
        };
        let mut output = Vec::new();
        execute_token(
            &context,
            "reader",
            &command(OutputFormat::Text),
            &mut output,
            || panic!("auto not expected"),
        )
        .unwrap();

        assert_eq!(output, b"still-live-child\n");
        assert!(client.request.borrow().is_none());
    }

    #[test]
    fn output_formats_and_writer_failures_are_exact() {
        let expiry = TokenExpiry::parse("2030-01-02T03:04:05Z").unwrap();
        let token = AccessToken::from("a'b");
        let mut text = Vec::new();
        write_token(
            &mut text,
            &token,
            expiry,
            "reader",
            "all",
            OutputFormat::Text,
        )
        .unwrap();
        assert_eq!(text, b"a'b\n");

        let mut env = Vec::new();
        write_token(&mut env, &token, expiry, "reader", "all", OutputFormat::Env).unwrap();
        assert_eq!(env, b"export GITHUB_TOKEN='a'\"'\"'b'\n");

        let mut failed = FailingWriter;
        assert!(
            write_token(
                &mut failed,
                &token,
                expiry,
                "reader",
                "all",
                OutputFormat::Json
            )
            .is_err()
        );
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("writer failed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
