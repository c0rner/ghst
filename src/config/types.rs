use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;

use crate::config::error::ConfigError;
use crate::domain::profile::{
    AppAuthority, AppCredentials, AppRegistration, PermissionLevel, RepoScope, ResolvedTokenProfile,
};

#[derive(PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub default_profile: Option<String>,
    #[serde(default)]
    pub no_browser: bool,
    #[serde(rename = "profile", default)]
    pub profiles: BTreeMap<String, ProfileConfig>,
}

impl Config {
    pub fn resolve_token_profile<'a>(
        &'a self,
        name: &str,
    ) -> Result<ResolvedTokenProfile<'a>, ConfigError> {
        let (stored_name, profile) = self
            .profiles
            .get_key_value(name)
            .ok_or_else(|| ConfigError::ProfileNotFound(name.to_owned()))?;

        match profile {
            ProfileConfig::App(app) => Ok(ResolvedTokenProfile::Base {
                name: stored_name.as_str(),
                app: AppRegistration {
                    authority: AppAuthority {
                        account: &app.github_app.account,
                        client_id: &app.github_app.client_id,
                    },
                    client_secret: app.github_app.client_secret.as_deref(),
                },
            }),
            ProfileConfig::Scoped(scoped) => {
                let (source_stored_name, source_profile) = self
                    .profiles
                    .get_key_value(&scoped.source)
                    .ok_or_else(|| ConfigError::ScopedSourceNotFound {
                        profile: stored_name.clone(),
                        source: scoped.source.clone(),
                    })?;
                let source_app = match source_profile {
                    ProfileConfig::App(app) => app,
                    ProfileConfig::Scoped(_) => {
                        return Err(ConfigError::ScopedFromNonApp {
                            profile: stored_name.clone(),
                            source: scoped.source.clone(),
                        });
                    }
                };
                let client_secret =
                    source_app
                        .github_app
                        .client_secret
                        .as_deref()
                        .ok_or_else(|| ConfigError::ScopedFromSecretlessApp {
                            profile: stored_name.clone(),
                            source: scoped.source.clone(),
                        })?;
                Ok(ResolvedTokenProfile::Scoped {
                    name: stored_name.as_str(),
                    source_name: source_stored_name.as_str(),
                    app: AppCredentials {
                        authority: AppAuthority {
                            account: &source_app.github_app.account,
                            client_id: &source_app.github_app.client_id,
                        },
                        client_secret,
                    },
                    repository_scope: &scoped.repo,
                    permissions: &scoped.permissions,
                })
            }
        }
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("version", &self.version)
            .field("default_profile", &self.default_profile)
            .field("no_browser", &self.no_browser)
            .field("profiles", &self.profiles)
            .finish()
    }
}

#[derive(PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ProfileConfig {
    App(AppProfile),
    Scoped(ScopedProfile),
}

impl ProfileConfig {
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::App(_) => "app",
            Self::Scoped(_) => "scoped",
        }
    }

    pub fn description(&self) -> Option<&str> {
        match self {
            Self::App(app) => app.description.as_deref(),
            Self::Scoped(scoped) => scoped.description.as_deref(),
        }
    }
}

impl fmt::Debug for ProfileConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::App(app) => f.debug_tuple("App").field(app).finish(),
            Self::Scoped(scoped) => f.debug_tuple("Scoped").field(scoped).finish(),
        }
    }
}

#[derive(PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppProfile {
    pub description: Option<String>,
    pub github_app: GitHubAppConfig,
}

impl fmt::Debug for AppProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppProfile")
            .field("description", &self.description)
            .field("github_app", &self.github_app)
            .finish()
    }
}

#[derive(PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAppConfig {
    pub account: String,
    pub client_id: String,
    pub client_secret: Option<String>,
}

// Hand-written Debug for GitHubAppConfig to prevent secret leaks
impl fmt::Debug for GitHubAppConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitHubAppConfig")
            .field("account", &self.account)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedProfile {
    pub description: Option<String>,
    pub source: String,
    #[serde(default)]
    pub repo: RepoScope,
    #[serde(default)]
    pub permissions: BTreeMap<String, PermissionLevel>,
}

impl fmt::Debug for ScopedProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedProfile")
            .field("description", &self.description)
            .field("source", &self.source)
            .field("repo", &self.repo)
            .field("permissions", &self.permissions)
            .finish()
    }
}
