use crate::repository::RepositoryError;
use std::path::Path;
use std::process::Command;

enum GitRepository {
    NotRepository,
    RepositoryWithoutOrigin,
    Repository { origin_url: String },
}

/// Resolves the canonical `owner/repo` for the `origin` remote through Git.
///
/// # Errors
///
/// Returns `RepositoryError` if no git repository is found, `origin` remote is missing,
/// URL is invalid, or the origin host is not GitHub (`github.com`).
pub fn resolve_origin_repo() -> Result<String, RepositoryError> {
    let cwd = std::env::current_dir()?;
    resolve_origin_repo_from(&cwd)
}

/// Resolves the canonical `owner/repo` for the `origin` remote starting search from `start_dir`.
///
/// # Errors
///
/// Returns `RepositoryError` if repository or `origin` is missing or invalid.
fn resolve_origin_repo_from(start_dir: &Path) -> Result<String, RepositoryError> {
    match discover_repository(start_dir)? {
        GitRepository::NotRepository => Err(RepositoryError::NotFound),
        GitRepository::RepositoryWithoutOrigin => Err(RepositoryError::OriginNotFound),
        GitRepository::Repository { origin_url } if origin_url.is_empty() => {
            Err(RepositoryError::MissingOriginUrl)
        }
        GitRepository::Repository { origin_url } => parse_github_owner_repo(&origin_url),
    }
}

fn discover_repository(start_dir: &Path) -> Result<GitRepository, RepositoryError> {
    let repository = Command::new("git")
        .arg("-C")
        .arg(start_dir)
        .args(["rev-parse", "--git-dir"])
        .output()?;
    if !repository.status.success() {
        return Ok(GitRepository::NotRepository);
    }

    let output = Command::new("git")
        .arg("-C")
        .arg(start_dir)
        .args(["remote", "get-url", "origin"])
        .output()?;
    match output.status.code() {
        Some(0) => {
            let url = std::str::from_utf8(&output.stdout)
                .map_err(|_| RepositoryError::InvalidOriginUrl)?
                .trim()
                .to_owned();
            Ok(GitRepository::Repository { origin_url: url })
        }
        Some(_) | None => Ok(GitRepository::RepositoryWithoutOrigin),
    }
}

/// Parses `owner/repo` from a GitHub remote URL.
/// Supports HTTPS, SSH, and SSH-URI formats.
/// Rejects non-GitHub domains with `RepositoryError::UnsupportedRemote`.
fn parse_github_owner_repo(url: &str) -> Result<String, RepositoryError> {
    let url_trimmed = url.trim();

    // Strip trailing .git if present
    let raw = url_trimmed.strip_suffix(".git").unwrap_or(url_trimmed);

    if let Some(rest) = raw.strip_prefix("git@")
        && let Some((host, path)) = rest.split_once(':')
    {
        if !host.eq_ignore_ascii_case("github.com") {
            return Err(RepositoryError::UnsupportedRemote {
                host: host.to_owned(),
            });
        }
        return extract_owner_repo_path(path, url);
    }

    if let Some(rest) = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("http://"))
        .or_else(|| raw.strip_prefix("ssh://"))
    {
        // Handle optional userinfo prefix in URL e.g. git@
        let rest = if let Some((_user, host_and_path)) = rest.rsplit_once('@') {
            host_and_path
        } else {
            rest
        };

        if let Some((host, path)) = rest.split_once('/') {
            if !host.eq_ignore_ascii_case("github.com") {
                return Err(RepositoryError::UnsupportedRemote {
                    host: host.to_owned(),
                });
            }
            return extract_owner_repo_path(path, url);
        }
    }

    Err(RepositoryError::InvalidOriginUrl)
}

fn extract_owner_repo_path(path: &str, _original_url: &str) -> Result<String, RepositoryError> {
    let mut parts = path
        .split('/')
        .map(str::trim)
        .filter(|part| !part.is_empty());
    if let (Some(owner), Some(repository), None) = (parts.next(), parts.next(), parts.next()) {
        return Ok(format!("{owner}/{repository}"));
    }

    Err(RepositoryError::InvalidOriginUrl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_github_url_formats() {
        assert_eq!(
            parse_github_owner_repo("git@github.com:c0rner/ghst.git").unwrap(),
            "c0rner/ghst"
        );
        assert_eq!(
            parse_github_owner_repo("git@github.com:octocat/Hello-World").unwrap(),
            "octocat/Hello-World"
        );
        assert_eq!(
            parse_github_owner_repo("https://github.com/octocat/Hello-World.git").unwrap(),
            "octocat/Hello-World"
        );
        assert_eq!(
            parse_github_owner_repo("https://github.com/owner/repo").unwrap(),
            "owner/repo"
        );
        assert_eq!(
            parse_github_owner_repo("ssh://git@github.com/owner/repo.git").unwrap(),
            "owner/repo"
        );
    }

    #[test]
    fn test_reject_non_github_remotes() {
        let err = parse_github_owner_repo("git@gitlab.com:owner/repo.git").unwrap_err();
        match err {
            RepositoryError::UnsupportedRemote { host } => {
                assert_eq!(host, "gitlab.com");
            }
            other => panic!("expected UnsupportedRemote, got {other:?}"),
        }

        let err_https =
            parse_github_owner_repo("https://bitbucket.org/owner/repo.git").unwrap_err();
        match err_https {
            RepositoryError::UnsupportedRemote { host } => {
                assert_eq!(host, "bitbucket.org");
            }
            other => panic!("expected UnsupportedRemote, got {other:?}"),
        }
    }

    #[test]
    fn errors_do_not_retain_credentials() {
        let marker = "secret-marker";
        for url in [
            format!("https://user:{marker}@gitlab.com/owner/repo.git"),
            format!("https://user:password@{marker}@gitlab.com/owner/repo.git"),
            format!("https://user:{marker}@github.com/not-enough"),
        ] {
            let error = parse_github_owner_repo(&url).unwrap_err();
            assert!(!error.to_string().contains(marker));
            assert!(!format!("{error:?}").contains(marker));
        }
    }

    #[test]
    fn distinguishes_non_repository_and_repository_without_origin() {
        let temp = tempfile::tempdir().unwrap();
        assert!(matches!(
            discover_repository(temp.path()).unwrap(),
            GitRepository::NotRepository
        ));
        assert!(matches!(
            resolve_origin_repo_from(temp.path()),
            Err(RepositoryError::NotFound)
        ));
        init_repository(temp.path());
        assert!(matches!(
            discover_repository(temp.path()).unwrap(),
            GitRepository::RepositoryWithoutOrigin
        ));
        assert!(matches!(
            resolve_origin_repo_from(temp.path()),
            Err(RepositoryError::OriginNotFound)
        ));
    }

    #[test]
    fn resolves_rewritten_origin_through_git() {
        let temp = tempfile::tempdir().unwrap();
        init_repository(temp.path());
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(temp.path())
                .args([
                    "config",
                    "url.https://github.com/.insteadOf",
                    "https://example.invalid/",
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(temp.path())
                .args([
                    "config",
                    "remote.origin.url",
                    "https://example.invalid/c0rner/ghst.git",
                ])
                .status()
                .unwrap()
                .success()
        );
        let nested = temp.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        assert_eq!(resolve_origin_repo_from(&nested).unwrap(), "c0rner/ghst");
    }

    fn init_repository(path: &Path) {
        assert!(
            Command::new("git")
                .args(["init", "--quiet"])
                .arg(path)
                .status()
                .unwrap()
                .success()
        );
    }
}
