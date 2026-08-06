use crate::config::RepoScope;
use crate::git::GitError;
use std::collections::BTreeSet;
use std::fmt;

#[derive(Debug)]
pub enum RepositoryError {
    Git(GitError),
    InvalidScope { value: String, reason: &'static str },
    OwnerMismatch { repository: String, account: String },
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Git(error) => write!(f, "{error}"),
            Self::InvalidScope { value, reason } => {
                write!(f, "invalid repository scope '{value}': {reason}")
            }
            Self::OwnerMismatch {
                repository,
                account,
            } => write!(
                f,
                "repository '{repository}' is not owned by configured target account '{account}'"
            ),
        }
    }
}

impl std::error::Error for RepositoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Git(error) => Some(error),
            Self::InvalidScope { .. } | Self::OwnerMismatch { .. } => None,
        }
    }
}

impl From<GitError> for RepositoryError {
    fn from(error: GitError) -> Self {
        Self::Git(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Repository {
    owner: String,
    name: String,
}

impl Repository {
    fn parse(value: &str) -> Result<Self, RepositoryError> {
        let Some((owner, name)) = value.split_once('/') else {
            return Err(invalid(value, "expected owner/repository"));
        };
        if owner.is_empty() || name.is_empty() || name.contains('/') {
            return Err(invalid(
                value,
                "expected exactly one non-empty owner/repository pair",
            ));
        }
        if !owner
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
        {
            return Err(invalid(value, "owner contains unsupported characters"));
        }
        if !name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        }) {
            return Err(invalid(value, "repository contains unsupported characters"));
        }
        Ok(Self {
            owner: owner.to_ascii_lowercase(),
            name: name.to_ascii_lowercase(),
        })
    }

    fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Selection {
    All,
    Selected(BTreeSet<Repository>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositorySelection {
    selection: Selection,
}

impl RepositorySelection {
    pub fn resolve(
        cli_values: &[String],
        configured: &RepoScope,
        mut resolve_auto: impl FnMut() -> Result<String, GitError>,
    ) -> Result<Self, RepositoryError> {
        let configured_value;
        let values = if cli_values.is_empty() {
            configured_value = configured.to_string();
            std::slice::from_ref(&configured_value)
        } else {
            cli_values
        };

        if values.iter().any(|value| value == "all") {
            if values.iter().any(|value| value != "all") {
                return Err(invalid(
                    &values.join(","),
                    "'all' cannot be combined with another repository selection",
                ));
            }
            return Ok(Self {
                selection: Selection::All,
            });
        }

        let mut repositories = BTreeSet::new();
        let mut automatic = None;
        for value in values {
            if value.is_empty() {
                return Err(invalid(value, "repository selection cannot be empty"));
            }
            let repository = if value == "auto" {
                if automatic.is_none() {
                    automatic = Some(Repository::parse(&resolve_auto()?)?);
                }
                automatic.as_ref().expect("automatic repository is set")
            } else {
                &Repository::parse(value)?
            };
            repositories.insert(repository.clone());
        }

        if repositories.is_empty() {
            return Err(invalid("", "at least one repository is required"));
        }
        Ok(Self {
            selection: Selection::Selected(repositories),
        })
    }

    pub fn canonical(&self) -> String {
        match &self.selection {
            Selection::All => "all".to_owned(),
            Selection::Selected(repositories) => repositories
                .iter()
                .map(Repository::full_name)
                .collect::<Vec<_>>()
                .join(","),
        }
    }

    pub fn repository_names(&self, account: &str) -> Result<Option<Vec<String>>, RepositoryError> {
        match &self.selection {
            Selection::All => Ok(None),
            Selection::Selected(repositories) => repositories
                .iter()
                .map(|repository| {
                    if repository.owner.eq_ignore_ascii_case(account) {
                        Ok(repository.name.clone())
                    } else {
                        Err(RepositoryError::OwnerMismatch {
                            repository: repository.full_name(),
                            account: account.to_owned(),
                        })
                    }
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Some),
        }
    }
}

impl fmt::Display for RepositorySelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}

fn invalid(value: &str, reason: &'static str) -> RepositoryError {
    RepositoryError::InvalidScope {
        value: value.to_owned(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_auto() -> Result<String, GitError> {
        panic!("auto resolver should not be called")
    }

    #[test]
    fn resolves_all_and_rejects_mixed_all() {
        assert_eq!(
            RepositorySelection::resolve(&["all".into()], &RepoScope::Auto, no_auto)
                .unwrap()
                .canonical(),
            "all"
        );
        assert!(matches!(
            RepositorySelection::resolve(
                &["all".into(), "acme/api".into()],
                &RepoScope::Auto,
                no_auto
            ),
            Err(RepositoryError::InvalidScope { .. })
        ));
    }

    #[test]
    fn resolves_auto_and_sorts_and_deduplicates() {
        let values = [
            "acme/zeta".into(),
            "auto".into(),
            "acme/zeta".into(),
            "acme/alpha".into(),
        ];
        let selection =
            RepositorySelection::resolve(&values, &RepoScope::All, || Ok("acme/middle".into()))
                .unwrap();
        assert_eq!(selection.canonical(), "acme/alpha,acme/middle,acme/zeta");
    }

    #[test]
    fn rejects_malformed_and_empty_repositories() {
        for value in [
            "",
            "owner",
            "/repo",
            "owner/",
            "one/two/three",
            "bad owner/repo",
        ] {
            assert!(matches!(
                RepositorySelection::resolve(&[value.into()], &RepoScope::All, no_auto),
                Err(RepositoryError::InvalidScope { .. })
            ));
        }
    }

    #[test]
    fn validates_owner_and_returns_only_repository_names() {
        let selection = RepositorySelection::resolve(
            &["acme/api".into(), "ACME/web".into()],
            &RepoScope::All,
            no_auto,
        )
        .unwrap();
        assert_eq!(
            selection.repository_names("acme").unwrap(),
            Some(vec!["api".into(), "web".into()])
        );

        let other =
            RepositorySelection::resolve(&["other/api".into()], &RepoScope::All, no_auto).unwrap();
        assert!(matches!(
            other.repository_names("acme"),
            Err(RepositoryError::OwnerMismatch { .. })
        ));
    }
}
