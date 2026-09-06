use crate::credential::provenance::ScopedProvenance;
use crate::credential::{AccessToken, TokenExpiry};
use crate::run::lifecycle::{RunLifecycle, RunLifecycleError, RunOwner, RunPhase};
use serde::{Deserialize, Serialize};
use std::fmt;
use time::OffsetDateTime;

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

    #[cfg(test)]
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
            (Self::Scoped(existing), Self::Scoped(candidate)) => existing
                .provenance()
                .mismatch(&candidate.provenance())
                .is_none(),
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
        model::generation_fingerprint(&self.access_token)
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

impl ScopedCacheEntry {
    pub fn provenance(&self) -> ScopedProvenance<'_> {
        ScopedProvenance {
            profile: &self.profile,
            source_profile: &self.source_profile,
            source_authority: &self.source_authority_fingerprint,
            repo_scope: &self.repo_scope,
            policy: &self.policy_fingerprint,
            parent_generation: &self.parent_generation,
        }
    }
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

impl RunCacheEntry {
    pub fn lifecycle(&self) -> Result<RunLifecycle<'_>, RunLifecycleError> {
        let phase = match (self.state, self.child_pid) {
            (RunState::Pending, None) => RunPhase::Pending,
            (RunState::Running, Some(child_pid)) => RunPhase::Running { child_pid },
            (RunState::CleanupPending, child_pid) => RunPhase::CleanupPending { child_pid },
            _ => return Err(RunLifecycleError::InvalidChild),
        };
        Ok(RunLifecycle::new(
            RunOwner {
                run_id: &self.run_id,
                wrapper_pid: self.wrapper_pid,
            },
            phase,
        ))
    }
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

use crate::credential::stored as model;
impl TryFrom<BaseCacheEntry> for model::StoredBase {
    type Error = crate::cache::CacheError;
    fn try_from(value: BaseCacheEntry) -> Result<Self, Self::Error> {
        if value.version != CACHE_SCHEMA_VERSION {
            return Err(Self::Error::UnsupportedSchema {
                kind: "base".into(),
                version: Some(value.version),
                expected: CACHE_SCHEMA_VERSION,
            });
        }
        Ok(Self {
            profile: value.profile,
            authority_fingerprint: value.authority_fingerprint,
            github_user: value.github_user,
            expires_at: value.expires_at,
            access_token: value.access_token,
        })
    }
}
impl From<&model::StoredBase> for BaseCacheEntry {
    fn from(value: &model::StoredBase) -> Self {
        Self {
            version: CACHE_SCHEMA_VERSION,
            profile: value.profile.clone(),
            authority_fingerprint: value.authority_fingerprint.clone(),
            github_user: value.github_user.clone(),
            expires_at: value.expires_at,
            access_token: AccessToken::from(value.access_token.as_ref()),
        }
    }
}
impl TryFrom<ScopedCacheEntry> for model::StoredScoped {
    type Error = crate::cache::CacheError;
    fn try_from(value: ScopedCacheEntry) -> Result<Self, Self::Error> {
        if value.version != CACHE_SCHEMA_VERSION {
            return Err(Self::Error::UnsupportedSchema {
                kind: "scoped".into(),
                version: Some(value.version),
                expected: CACHE_SCHEMA_VERSION,
            });
        }
        Ok(Self {
            profile: value.profile,
            source_profile: value.source_profile,
            source_authority_fingerprint: value.source_authority_fingerprint,
            parent_generation: value.parent_generation,
            policy_fingerprint: value.policy_fingerprint,
            github_user: value.github_user,
            repo_scope: value.repo_scope,
            expires_at: value.expires_at,
            access_token: value.access_token,
        })
    }
}
impl From<&model::StoredScoped> for ScopedCacheEntry {
    fn from(value: &model::StoredScoped) -> Self {
        Self {
            version: CACHE_SCHEMA_VERSION,
            profile: value.profile.clone(),
            source_profile: value.source_profile.clone(),
            source_authority_fingerprint: value.source_authority_fingerprint.clone(),
            parent_generation: value.parent_generation.clone(),
            policy_fingerprint: value.policy_fingerprint.clone(),
            github_user: value.github_user.clone(),
            repo_scope: value.repo_scope.clone(),
            expires_at: value.expires_at,
            access_token: AccessToken::from(value.access_token.as_ref()),
        }
    }
}
impl TryFrom<RunCacheEntry> for model::StoredRun {
    type Error = crate::cache::CacheError;
    fn try_from(value: RunCacheEntry) -> Result<Self, Self::Error> {
        if value.version != RUN_CACHE_SCHEMA_VERSION {
            return Err(Self::Error::UnsupportedSchema {
                kind: "run".into(),
                version: Some(value.version),
                expected: RUN_CACHE_SCHEMA_VERSION,
            });
        }
        let phase = match (value.state, value.child_pid) {
            (RunState::Pending, None) => RunPhase::Pending,
            (RunState::Running, Some(child_pid)) => RunPhase::Running { child_pid },
            (RunState::CleanupPending, child_pid) => RunPhase::CleanupPending { child_pid },
            _ => return Err(RunLifecycleError::InvalidChild.into()),
        };
        Ok(Self {
            run_id: value.run_id,
            wrapper_pid: value.wrapper_pid,
            command: value.command,
            profile: value.profile,
            source_profile: value.source_profile,
            source_authority_fingerprint: value.source_authority_fingerprint,
            github_user: value.github_user,
            repo_scope: value.repo_scope,
            expires_at: value.expires_at,
            access_token: value.access_token,
            phase,
        })
    }
}
impl From<&model::StoredRun> for RunCacheEntry {
    fn from(value: &model::StoredRun) -> Self {
        Self {
            version: RUN_CACHE_SCHEMA_VERSION,
            run_id: value.run_id.clone(),
            state: match value.phase {
                RunPhase::Pending => RunState::Pending,
                RunPhase::Running { .. } => RunState::Running,
                RunPhase::CleanupPending { .. } => RunState::CleanupPending,
            },
            wrapper_pid: value.wrapper_pid,
            child_pid: value.child_pid(),
            command: value.command.clone(),
            profile: value.profile.clone(),
            source_profile: value.source_profile.clone(),
            source_authority_fingerprint: value.source_authority_fingerprint.clone(),
            github_user: value.github_user.clone(),
            repo_scope: value.repo_scope.clone(),
            expires_at: value.expires_at,
            access_token: AccessToken::from(value.access_token.as_ref()),
        }
    }
}
impl TryFrom<CacheEntry> for model::StoredCredential {
    type Error = crate::cache::CacheError;
    fn try_from(value: CacheEntry) -> Result<Self, Self::Error> {
        match value {
            CacheEntry::Base(v) => Ok(Self::Base(v.try_into()?)),
            CacheEntry::Scoped(v) => Ok(Self::Scoped(v.try_into()?)),
            CacheEntry::Run(v) => Ok(Self::Run(v.try_into()?)),
        }
    }
}
impl From<&model::StoredCredential> for CacheEntry {
    fn from(value: &model::StoredCredential) -> Self {
        match value {
            model::StoredCredential::Base(v) => Self::Base(v.into()),
            model::StoredCredential::Scoped(v) => Self::Scoped(v.into()),
            model::StoredCredential::Run(v) => Self::Run(v.into()),
        }
    }
}

impl From<model::StoredRun> for RunCacheEntry {
    fn from(value: model::StoredRun) -> Self {
        let child_pid = value.child_pid();
        Self {
            version: RUN_CACHE_SCHEMA_VERSION,
            state: match value.phase {
                RunPhase::Pending => RunState::Pending,
                RunPhase::Running { .. } => RunState::Running,
                RunPhase::CleanupPending { .. } => RunState::CleanupPending,
            },
            child_pid,
            run_id: value.run_id,
            wrapper_pid: value.wrapper_pid,
            command: value.command,
            profile: value.profile,
            source_profile: value.source_profile,
            source_authority_fingerprint: value.source_authority_fingerprint,
            github_user: value.github_user,
            repo_scope: value.repo_scope,
            expires_at: value.expires_at,
            access_token: value.access_token,
        }
    }
}
impl RunCacheEntry {
    pub(super) fn matches_stored(&self, value: &model::StoredRun) -> bool {
        self.lifecycle().is_ok()
            && self.child_pid == value.child_pid()
            && matches!(
                (self.state, value.phase),
                (RunState::Pending, RunPhase::Pending)
                    | (RunState::Running, RunPhase::Running { .. })
                    | (RunState::CleanupPending, RunPhase::CleanupPending { .. })
            )
            && self.run_id == value.run_id
            && self.wrapper_pid == value.wrapper_pid
            && self.command == value.command
            && self.profile == value.profile
            && self.source_profile == value.source_profile
            && self.source_authority_fingerprint == value.source_authority_fingerprint
            && self.github_user == value.github_user
            && self.repo_scope == value.repo_scope
            && self.expires_at == value.expires_at
            && self.access_token == value.access_token
    }
}
