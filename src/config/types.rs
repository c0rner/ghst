use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub version: u32,
    pub default_profile: Option<String>,
    #[serde(default)]
    pub no_browser: Option<bool>,
    #[serde(rename = "profile", default)]
    pub profiles: BTreeMap<String, ProfileConfig>,
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProfileConfig {
    Root(RootProfile),
    Derived(DerivedProfile),
}

impl fmt::Debug for ProfileConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root(root) => f.debug_tuple("Root").field(root).finish(),
            Self::Derived(derived) => f.debug_tuple("Derived").field(derived).finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootProfile {
    pub description: Option<String>,
    pub github_app: GitHubAppConfig,
    pub repo: Option<RepoScope>,
}

impl fmt::Debug for RootProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootProfile")
            .field("description", &self.description)
            .field("github_app", &self.github_app)
            .field("repo", &self.repo)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHubAppConfig {
    pub account: String,
    pub client_id: String,
    pub client_secret: String,
}

// Hand-written Debug for GitHubAppConfig to prevent secret leaks
impl fmt::Debug for GitHubAppConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitHubAppConfig")
            .field("account", &self.account)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

const fn default_derived_repo() -> RepoScope {
    RepoScope::Auto
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedProfile {
    pub description: Option<String>,
    pub source: String,
    #[serde(default = "default_derived_repo")]
    pub repo: RepoScope,
    #[serde(default)]
    pub permissions: BTreeMap<String, PermissionLevel>,
}

impl fmt::Debug for DerivedProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedProfile")
            .field("description", &self.description)
            .field("source", &self.source)
            .field("repo", &self.repo)
            .field("permissions", &self.permissions)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoScope {
    All,
    Auto,
    #[serde(untagged)]
    Specific(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionLevel {
    Read,
    Write,
    None,
}
