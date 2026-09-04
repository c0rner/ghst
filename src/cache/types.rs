use crate::cache::digest::encode_hex;
use crate::domain::credential::{AccessToken, TokenExpiry};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub const CACHE_SCHEMA_VERSION: u32 = 5;
pub const RUN_CACHE_SCHEMA_VERSION: u32 = 3;

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CacheEntry {
    Base(BaseCacheEntry),
    Scoped(ScopedCacheEntry),
    Run(RunCacheEntry),
}

impl CacheEntry {
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Base(_) => "base",
            Self::Scoped(_) => "scoped",
            Self::Run(_) => "run",
        }
    }

    pub fn profile(&self) -> &str {
        match self {
            Self::Base(entry) => &entry.profile,
            Self::Scoped(entry) => &entry.profile,
            Self::Run(entry) => &entry.profile,
        }
    }

    pub fn repo_scope(&self) -> &str {
        match self {
            Self::Base(_) => "all",
            Self::Scoped(entry) => &entry.repo_scope,
            Self::Run(entry) => &entry.repo_scope,
        }
    }

    pub const fn access_token(&self) -> &AccessToken {
        match self {
            Self::Base(entry) => &entry.access_token,
            Self::Scoped(entry) => &entry.access_token,
            Self::Run(entry) => &entry.access_token,
        }
    }

    pub const fn is_current(&self) -> bool {
        match self {
            Self::Base(entry) => entry.version == CACHE_SCHEMA_VERSION,
            Self::Scoped(entry) => entry.version == CACHE_SCHEMA_VERSION,
            Self::Run(entry) => entry.version == RUN_CACHE_SCHEMA_VERSION,
        }
    }

    pub fn is_safe_to_handoff_at(&self, now: OffsetDateTime) -> bool {
        match self {
            Self::Base(entry) => entry.expires_at.is_safe_to_handoff_at(now),
            Self::Scoped(entry) => entry.expires_at.is_safe_to_handoff_at(now),
            Self::Run(entry) => entry.expires_at.is_safe_to_handoff_at(now),
        }
    }

    pub fn compatible_with(&self, candidate: &Self, now: OffsetDateTime) -> bool {
        if !self.is_current() || !self.is_safe_to_handoff_at(now) {
            return false;
        }

        match (self, candidate) {
            (Self::Base(existing), Self::Base(candidate)) => {
                existing.profile == candidate.profile
                    && existing.authority_fingerprint == candidate.authority_fingerprint
            }
            (Self::Scoped(existing), Self::Scoped(candidate)) => {
                existing.profile == candidate.profile
                    && existing.source_profile == candidate.source_profile
                    && existing.source_authority_fingerprint
                        == candidate.source_authority_fingerprint
                    && existing.repo_scope == candidate.repo_scope
                    && existing.parent_generation == candidate.parent_generation
                    && existing.policy_fingerprint == candidate.policy_fingerprint
            }
            _ => false,
        }
    }
}

impl fmt::Debug for CacheEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base(entry) => f.debug_tuple("Base").field(entry).finish(),
            Self::Scoped(entry) => f.debug_tuple("Scoped").field(entry).finish(),
            Self::Run(entry) => f.debug_tuple("Run").field(entry).finish(),
        }
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseCacheEntry {
    pub version: u32,
    pub profile: String,
    pub authority_fingerprint: String,
    pub github_user: String,
    pub expires_at: TokenExpiry,
    pub access_token: AccessToken,
}

impl BaseCacheEntry {
    pub fn generation_fingerprint(&self) -> String {
        fingerprint(&[self.access_token.as_ref()])
    }
}

impl fmt::Debug for BaseCacheEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BaseCacheEntry")
            .field("version", &self.version)
            .field("profile", &self.profile)
            .field("authority_fingerprint", &self.authority_fingerprint)
            .field("github_user", &self.github_user)
            .field("expires_at", &self.expires_at)
            .field("access_token", &self.access_token)
            .finish()
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedCacheEntry {
    pub version: u32,
    pub profile: String,
    pub source_profile: String,
    pub source_authority_fingerprint: String,
    pub parent_generation: String,
    pub policy_fingerprint: String,
    pub github_user: String,
    pub repo_scope: String,
    pub expires_at: TokenExpiry,
    pub access_token: AccessToken,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Pending,
    Running,
    CleanupPending,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunCacheEntry {
    pub version: u32,
    pub run_id: String,
    pub state: RunState,
    pub wrapper_pid: u32,
    pub child_pid: Option<u32>,
    pub command: String,
    pub profile: String,
    pub source_profile: String,
    pub source_authority_fingerprint: String,
    pub github_user: String,
    pub repo_scope: String,
    pub expires_at: TokenExpiry,
    pub access_token: AccessToken,
}

impl fmt::Debug for RunCacheEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunCacheEntry")
            .field("version", &self.version)
            .field("run_id", &self.run_id)
            .field("state", &self.state)
            .field("wrapper_pid", &self.wrapper_pid)
            .field("child_pid", &self.child_pid)
            .field("command", &"[REDACTED]")
            .field("profile", &self.profile)
            .field("source_profile", &self.source_profile)
            .field(
                "source_authority_fingerprint",
                &self.source_authority_fingerprint,
            )
            .field("github_user", &self.github_user)
            .field("repo_scope", &self.repo_scope)
            .field("expires_at", &self.expires_at)
            .field("access_token", &self.access_token)
            .finish()
    }
}

impl fmt::Debug for ScopedCacheEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedCacheEntry")
            .field("version", &self.version)
            .field("profile", &self.profile)
            .field("source_profile", &self.source_profile)
            .field(
                "source_authority_fingerprint",
                &self.source_authority_fingerprint,
            )
            .field("parent_generation", &self.parent_generation)
            .field("policy_fingerprint", &self.policy_fingerprint)
            .field("github_user", &self.github_user)
            .field("repo_scope", &self.repo_scope)
            .field("expires_at", &self.expires_at)
            .field("access_token", &self.access_token)
            .finish()
    }
}

/// Result of attempting to persist an immutable cache entry.
#[derive(Debug)]
pub enum SaveCacheEntry {
    Saved,
    Retained(Box<CacheEntry>),
}

/// Result of atomically replacing the exact scoped entry selected for renewal.
#[derive(Debug)]
pub enum ReplaceCacheEntry {
    Replaced(Box<CacheEntry>),
    Retained(Box<CacheEntry>),
}

pub fn format_rfc3339(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_default()
}

pub fn authority_fingerprint(client_id: &str, account: &str) -> String {
    fingerprint(&[client_id, account])
}

pub fn policy_fingerprint<V: fmt::Display>(
    account: &str,
    repo_scope: &str,
    permissions: &BTreeMap<String, V>,
) -> String {
    let permission_string = permissions
        .iter()
        .map(|(name, level)| format!("{name}={level}"))
        .collect::<Vec<_>>()
        .join("\n");
    fingerprint(&[account, repo_scope, &permission_string])
}

fn fingerprint(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize();
    encode_hex(&digest)
}
