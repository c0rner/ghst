use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum GitError {
    RepositoryNotFound,
    OriginRemoteNotFound,
    MissingUrl,
    NonGitHubRemote(String),
    InvalidRepoUrl(String),
    Io(std::io::Error),
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RepositoryNotFound => {
                write!(
                    f,
                    "could not find .git repository in current or parent directories"
                )
            }
            Self::OriginRemoteNotFound => {
                write!(f, "'origin' remote is not defined in .git/config")
            }
            Self::MissingUrl => write!(f, "'origin' remote in .git/config is missing a URL"),
            Self::NonGitHubRemote(url) => write!(
                f,
                "origin remote '{url}' is not a GitHub repository. ghst is tailored for GitHub only"
            ),
            Self::InvalidRepoUrl(url) => {
                write!(
                    f,
                    "could not parse owner/repository from origin URL '{url}'"
                )
            }
            Self::Io(err) => write!(f, "git IO error: {err}"),
        }
    }
}

impl std::error::Error for GitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

/// Resolves the canonical `owner/repo` for the `origin` remote by inspecting local `.git/config`.
///
/// # Errors
///
/// Returns `GitError` if no git repository is found, `origin` remote is missing,
/// URL is invalid, or the origin host is not GitHub (`github.com`).
pub fn resolve_origin_repo() -> Result<String, GitError> {
    let cwd = std::env::current_dir().map_err(GitError::Io)?;
    resolve_origin_repo_from(&cwd)
}

/// Resolves the canonical `owner/repo` for the `origin` remote starting search from `start_dir`.
///
/// # Errors
///
/// Returns `GitError` if repository or `origin` is missing or invalid.
pub fn resolve_origin_repo_from(start_dir: &Path) -> Result<String, GitError> {
    let config_path = find_git_config_path(start_dir)?;
    let content = fs::read_to_string(&config_path).map_err(GitError::Io)?;
    let url = parse_origin_url_from_config(&content)?;
    parse_github_owner_repo(&url)
}

/// Finds the path to `.git/config` by walking up parent directories starting from `start_dir`.
fn find_git_config_path(start_dir: &Path) -> Result<PathBuf, GitError> {
    let mut current = start_dir.to_path_buf();
    loop {
        let git_path = current.join(".git");
        if git_path.is_dir() {
            let config = git_path.join("config");
            if config.is_file() {
                return Ok(config);
            }
        } else if git_path.is_file() {
            // Worktree or submodule .git file pointing to gitdir
            if let Ok(content) = fs::read_to_string(&git_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if let Some(gitdir) = line.strip_prefix("gitdir:") {
                        let gitdir = gitdir.trim();
                        let gitdir_path = current.join(gitdir);
                        let config = gitdir_path.join("config");
                        if config.is_file() {
                            return Ok(config);
                        }
                    }
                }
            }
        }

        if !current.pop() {
            break;
        }
    }
    Err(GitError::RepositoryNotFound)
}

/// Parses `[remote "origin"]` section from `.git/config` content and returns its `url`.
pub fn parse_origin_url_from_config(config_content: &str) -> Result<String, GitError> {
    let mut in_origin_section = false;
    for line in config_content.lines() {
        let line = line.trim();

        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim();
            // Handle [remote "origin"] or [remote 'origin'] or [remote origin]
            in_origin_section = section.eq_ignore_ascii_case(r#"remote "origin""#)
                || section.eq_ignore_ascii_case("remote 'origin'")
                || section.eq_ignore_ascii_case("remote origin");
            continue;
        }

        if in_origin_section && let Some((key, val)) = line.split_once('=') {
            let key = key.trim();
            let val = val.trim();
            if key.eq_ignore_ascii_case("url") {
                if val.is_empty() {
                    return Err(GitError::MissingUrl);
                }
                return Ok(val.to_string());
            }
        }
    }

    Err(GitError::OriginRemoteNotFound)
}

/// Parses `owner/repo` from a GitHub remote URL.
/// Supports HTTPS, SSH, and SSH-URI formats.
/// Rejects non-GitHub domains with `GitError::NonGitHubRemote`.
pub fn parse_github_owner_repo(url: &str) -> Result<String, GitError> {
    let url_trimmed = url.trim();

    // Strip trailing .git if present
    let raw = url_trimmed.strip_suffix(".git").unwrap_or(url_trimmed);

    // 1. SSH format: git@github.com:owner/repo
    if let Some(rest) = raw.strip_prefix("git@")
        && let Some((host, path)) = rest.split_once(':')
    {
        if !host.eq_ignore_ascii_case("github.com") {
            return Err(GitError::NonGitHubRemote(url.to_string()));
        }
        return extract_owner_repo_path(path, url);
    }

    // 2. URL format: https://github.com/owner/repo or ssh://git@github.com/owner/repo or http://github.com/owner/repo
    if raw.starts_with("https://") || raw.starts_with("http://") || raw.starts_with("ssh://") {
        let rest = raw
            .strip_prefix("https://")
            .or_else(|| raw.strip_prefix("http://"))
            .or_else(|| raw.strip_prefix("ssh://"))
            .unwrap();

        // Handle optional userinfo prefix in URL e.g. git@
        let rest = if let Some((_user, host_and_path)) = rest.split_once('@') {
            host_and_path
        } else {
            rest
        };

        if let Some((host, path)) = rest.split_once('/') {
            if !host.eq_ignore_ascii_case("github.com") {
                return Err(GitError::NonGitHubRemote(url.to_string()));
            }
            return extract_owner_repo_path(path, url);
        }
    }

    Err(GitError::InvalidRepoUrl(url.to_string()))
}

fn extract_owner_repo_path(path: &str, original_url: &str) -> Result<String, GitError> {
    let parts: Vec<&str> = path
        .split('/')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if parts.len() == 2 {
        let owner = parts[0];
        let repo = parts[1];
        if !owner.is_empty() && !repo.is_empty() {
            return Ok(format!("{owner}/{repo}"));
        }
    }

    Err(GitError::InvalidRepoUrl(original_url.to_string()))
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
            GitError::NonGitHubRemote(url) => {
                assert_eq!(url, "git@gitlab.com:owner/repo.git");
            }
            other => panic!("expected NonGitHubRemote, got {other:?}"),
        }

        let err_https =
            parse_github_owner_repo("https://bitbucket.org/owner/repo.git").unwrap_err();
        match err_https {
            GitError::NonGitHubRemote(url) => {
                assert_eq!(url, "https://bitbucket.org/owner/repo.git");
            }
            other => panic!("expected NonGitHubRemote, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_origin_url_from_config() {
        let config = r#"
[core]
	repositoryformatversion = 0
	filemode = true
[remote "origin"]
	url = git@github.com:c0rner/ghst.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
"#;
        let url = parse_origin_url_from_config(config).unwrap();
        assert_eq!(url, "git@github.com:c0rner/ghst.git");
    }

    #[test]
    fn test_missing_origin_remote() {
        let config = r#"
[core]
	repositoryformatversion = 0
[remote "upstream"]
	url = git@github.com:c0rner/ghst.git
"#;
        let err = parse_origin_url_from_config(config).unwrap_err();
        match err {
            GitError::OriginRemoteNotFound => {}
            other => panic!("expected OriginRemoteNotFound, got {other:?}"),
        }
    }
}
