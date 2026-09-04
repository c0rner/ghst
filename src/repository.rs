use std::collections::BTreeSet;
use std::fmt;

use crate::domain::profile::RepoScope;

#[derive(Debug)]
pub enum RepositoryError {
    NotFound,
    OriginNotFound,
    MissingOriginUrl,
    UnsupportedRemote { host: String },
    InvalidOriginUrl,
    InvalidScope { value: String, reason: &'static str },
    OwnerMismatch { repository: String, account: String },
    Io(std::io::Error),
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(
                f,
                "could not find .git repository in current or parent directories"
            ),
            Self::OriginNotFound => write!(f, "repository does not define an 'origin' remote"),
            Self::MissingOriginUrl => {
                write!(f, "repository's 'origin' remote is missing a URL")
            }
            Self::UnsupportedRemote { host } => write!(
                f,
                "origin remote host '{host}' is not GitHub. ghst is tailored for GitHub only"
            ),
            Self::InvalidOriginUrl => write!(f, "could not parse owner/repository from origin URL"),
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
            Self::Io(error) => write!(f, "git IO error: {error}"),
        }
    }
}

impl std::error::Error for RepositoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::NotFound
            | Self::OriginNotFound
            | Self::MissingOriginUrl
            | Self::UnsupportedRemote { .. }
            | Self::InvalidOriginUrl
            | Self::InvalidScope { .. }
            | Self::OwnerMismatch { .. } => None,
        }
    }
}

impl From<std::io::Error> for RepositoryError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
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
        account: &str,
        mut resolve_auto: impl FnMut() -> Result<String, RepositoryError>,
    ) -> Result<Self, RepositoryError> {
        let configured_value;
        let values = if cli_values.is_empty() {
            match configured {
                RepoScope::Multiple(repositories) => repositories,
                RepoScope::All | RepoScope::Auto | RepoScope::Specific(_) => {
                    configured_value = configured.to_string();
                    std::slice::from_ref(&configured_value)
                }
            }
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
        let mut automatic_resolved = false;
        for value in values {
            if value.is_empty() {
                return Err(invalid(value, "repository selection cannot be empty"));
            }
            if value == "auto" && automatic_resolved {
                continue;
            }
            let repository = if value == "auto" {
                automatic_resolved = true;
                Repository::parse(&resolve_auto()?)?
            } else {
                Repository::parse(value)?
            };
            if !repository.owner.eq_ignore_ascii_case(account) {
                return Err(RepositoryError::OwnerMismatch {
                    repository: repository.full_name(),
                    account: account.to_owned(),
                });
            }
            repositories.insert(repository);
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

    pub fn repository_names(&self) -> Option<Vec<String>> {
        match &self.selection {
            Selection::All => None,
            Selection::Selected(repositories) => Some(
                repositories
                    .iter()
                    .map(|repository| repository.name.clone())
                    .collect(),
            ),
        }
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

    fn no_auto() -> Result<String, RepositoryError> {
        panic!("auto resolver should not be called")
    }

    #[test]
    fn resolves_all_and_rejects_mixed_all() {
        assert_eq!(
            RepositorySelection::resolve(&["all".into()], &RepoScope::Auto, "acme", no_auto)
                .unwrap()
                .canonical(),
            "all"
        );
        assert!(matches!(
            RepositorySelection::resolve(
                &["all".into(), "acme/api".into()],
                &RepoScope::Auto,
                "acme",
                no_auto
            ),
            Err(RepositoryError::InvalidScope { .. })
        ));
        assert!(matches!(
            RepositorySelection::resolve(
                &[],
                &RepoScope::Multiple(Vec::from(["all".to_owned(), "acme/api".to_owned(),])),
                "acme",
                no_auto
            ),
            Err(RepositoryError::InvalidScope { .. })
        ));
    }

    #[test]
    fn resolves_configured_auto_and_sorts_and_deduplicates() {
        let configured = RepoScope::Multiple(Vec::from([
            "acme/zeta".into(),
            "auto".into(),
            "auto".into(),
            "acme/zeta".into(),
            "acme/alpha".into(),
        ]));
        let auto_calls = std::cell::Cell::new(0);
        let selection = RepositorySelection::resolve(&[], &configured, "acme", || {
            auto_calls.set(auto_calls.get() + 1);
            Ok("acme/middle".into())
        })
        .unwrap();
        assert_eq!(selection.canonical(), "acme/alpha,acme/middle,acme/zeta");
        assert_eq!(auto_calls.get(), 1);
    }

    #[test]
    fn cli_values_replace_the_complete_configured_selection() {
        let configured =
            RepoScope::Multiple(Vec::from(["acme/configured".to_owned(), "auto".to_owned()]));
        let selection = RepositorySelection::resolve(
            &["acme/override".to_owned()],
            &configured,
            "acme",
            no_auto,
        )
        .unwrap();
        assert_eq!(selection.canonical(), "acme/override");
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
                RepositorySelection::resolve(&[value.into()], &RepoScope::All, "owner", no_auto),
                Err(RepositoryError::InvalidScope { .. })
            ));
        }
        assert!(matches!(
            RepositorySelection::resolve(&[], &RepoScope::Multiple(Vec::new()), "owner", no_auto),
            Err(RepositoryError::InvalidScope { .. })
        ));
    }

    #[test]
    fn validates_owner_and_returns_only_repository_names() {
        let selection = RepositorySelection::resolve(
            &["acme/api".into(), "ACME/web".into()],
            &RepoScope::All,
            "acme",
            no_auto,
        )
        .unwrap();
        assert_eq!(
            selection.repository_names(),
            Some(vec!["api".into(), "web".into()])
        );

        assert!(matches!(
            RepositorySelection::resolve(&["other/api".into()], &RepoScope::All, "acme", no_auto),
            Err(RepositoryError::OwnerMismatch { .. })
        ));
        assert!(matches!(
            RepositorySelection::resolve(&["auto".into()], &RepoScope::All, "acme", || {
                Ok("other/api".into())
            }),
            Err(RepositoryError::OwnerMismatch { .. })
        ));
    }
}
