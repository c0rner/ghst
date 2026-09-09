use super::error::CacheError;
use crate::credential::{AccessToken, BaseCredential, ScopedCredential, TokenExpiry};
use crate::run::{RunRecord, RunState};
use serde::{Deserialize, Serialize};
use std::fmt;
use time::OffsetDateTime;

pub(super) const CACHE_SCHEMA_VERSION: u32 = 5;
pub(super) const RUN_CACHE_SCHEMA_VERSION: u32 = 3;

/// Non-serializable adapter result containing feature models.
#[derive(PartialEq, Eq)]
pub enum Record {
    Base(BaseCredential),
    Scoped(ScopedCredential),
    Run(RunRecord),
}

impl Record {
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

    pub const fn expires_at(&self) -> TokenExpiry {
        match self {
            Self::Base(entry) => entry.expires_at,
            Self::Scoped(entry) => entry.expires_at,
            Self::Run(entry) => entry.expires_at,
        }
    }

    pub fn is_safe_to_handoff_at(&self, now: OffsetDateTime) -> bool {
        self.expires_at().is_safe_to_handoff_at(now)
    }

    pub fn compatible_with(&self, candidate: &Self, now: OffsetDateTime) -> bool {
        match (self, candidate) {
            (Self::Base(existing), Self::Base(candidate)) => {
                existing.compatible_with(candidate, now)
            }
            (Self::Scoped(existing), Self::Scoped(candidate)) => {
                existing.compatible_with(candidate, now)
            }
            _ => false,
        }
    }
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base(entry) => f.debug_tuple("Base").field(entry).finish(),
            Self::Scoped(entry) => f.debug_tuple("Scoped").field(entry).finish(),
            Self::Run(entry) => f.debug_tuple("Run").field(entry).finish(),
        }
    }
}

/// Result of attempting to persist an immutable cache entry.
#[derive(Debug)]
pub enum SaveCacheEntry {
    Saved,
    Retained(Box<Record>),
}

/// Result of atomically replacing the exact scoped entry selected for renewal.
#[derive(Debug)]
pub enum ReplaceCacheEntry {
    Replaced(Box<Record>),
    Retained(Box<Record>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RunStateDto {
    Pending,
    Running,
    CleanupPending,
}

impl From<RunState> for RunStateDto {
    fn from(state: RunState) -> Self {
        match state {
            RunState::Pending => Self::Pending,
            RunState::Running => Self::Running,
            RunState::CleanupPending => Self::CleanupPending,
        }
    }
}

impl From<RunStateDto> for RunState {
    fn from(dto: RunStateDto) -> Self {
        match dto {
            RunStateDto::Pending => Self::Pending,
            RunStateDto::Running => Self::Running,
            RunStateDto::CleanupPending => Self::CleanupPending,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum CacheEntryDto {
    Base(BaseCacheEntryDto),
    Scoped(ScopedCacheEntryDto),
    Run(RunCacheEntryDto),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BaseCacheEntryDto {
    pub version: u32,
    pub profile: String,
    pub authority_fingerprint: String,
    pub github_user: String,
    pub expires_at: TokenExpiry,
    pub access_token: AccessToken,
}

impl fmt::Debug for BaseCacheEntryDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BaseCacheEntryDto")
            .field("version", &self.version)
            .field("profile", &self.profile)
            .field("authority_fingerprint", &self.authority_fingerprint)
            .field("github_user", &self.github_user)
            .field("expires_at", &self.expires_at)
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ScopedCacheEntryDto {
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

impl fmt::Debug for ScopedCacheEntryDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedCacheEntryDto")
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
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RunCacheEntryDto {
    pub version: u32,
    pub run_id: String,
    pub state: RunStateDto,
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

impl fmt::Debug for RunCacheEntryDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunCacheEntryDto")
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
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

impl TryFrom<BaseCacheEntryDto> for BaseCredential {
    type Error = CacheError;

    fn try_from(dto: BaseCacheEntryDto) -> Result<Self, Self::Error> {
        if dto.version != CACHE_SCHEMA_VERSION {
            return Err(CacheError::UnsupportedSchema {
                kind: "base".to_string(),
                version: Some(dto.version),
                expected: CACHE_SCHEMA_VERSION,
            });
        }
        Ok(Self {
            profile: dto.profile,
            authority_fingerprint: dto.authority_fingerprint,
            github_user: dto.github_user,
            expires_at: dto.expires_at,
            access_token: dto.access_token,
        })
    }
}

impl TryFrom<ScopedCacheEntryDto> for ScopedCredential {
    type Error = CacheError;

    fn try_from(dto: ScopedCacheEntryDto) -> Result<Self, Self::Error> {
        if dto.version != CACHE_SCHEMA_VERSION {
            return Err(CacheError::UnsupportedSchema {
                kind: "scoped".to_string(),
                version: Some(dto.version),
                expected: CACHE_SCHEMA_VERSION,
            });
        }
        Ok(Self {
            profile: dto.profile,
            source_profile: dto.source_profile,
            source_authority_fingerprint: dto.source_authority_fingerprint,
            parent_generation: dto.parent_generation,
            policy_fingerprint: dto.policy_fingerprint,
            github_user: dto.github_user,
            repo_scope: dto.repo_scope,
            expires_at: dto.expires_at,
            access_token: dto.access_token,
        })
    }
}

impl TryFrom<RunCacheEntryDto> for RunRecord {
    type Error = CacheError;

    fn try_from(dto: RunCacheEntryDto) -> Result<Self, Self::Error> {
        if dto.version != RUN_CACHE_SCHEMA_VERSION {
            return Err(CacheError::UnsupportedSchema {
                kind: "run".to_string(),
                version: Some(dto.version),
                expected: RUN_CACHE_SCHEMA_VERSION,
            });
        }
        Ok(Self {
            run_id: dto.run_id,
            state: dto.state.into(),
            wrapper_pid: dto.wrapper_pid,
            child_pid: dto.child_pid,
            command: dto.command,
            profile: dto.profile,
            source_profile: dto.source_profile,
            source_authority_fingerprint: dto.source_authority_fingerprint,
            github_user: dto.github_user,
            repo_scope: dto.repo_scope,
            expires_at: dto.expires_at,
            access_token: dto.access_token,
        })
    }
}

impl TryFrom<CacheEntryDto> for Record {
    type Error = CacheError;

    fn try_from(dto: CacheEntryDto) -> Result<Self, Self::Error> {
        match dto {
            CacheEntryDto::Base(dto) => dto.try_into().map(Self::Base),
            CacheEntryDto::Scoped(dto) => dto.try_into().map(Self::Scoped),
            CacheEntryDto::Run(dto) => dto.try_into().map(Self::Run),
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum RecordWriteView<'a> {
    Base(BaseRecordWriteView<'a>),
    Scoped(ScopedRecordWriteView<'a>),
    Run(RunRecordWriteView<'a>),
}

#[derive(Serialize)]
pub(super) struct BaseRecordWriteView<'a> {
    pub version: u32,
    pub profile: &'a str,
    pub authority_fingerprint: &'a str,
    pub github_user: &'a str,
    pub expires_at: TokenExpiry,
    pub access_token: &'a AccessToken,
}

#[derive(Serialize)]
pub(super) struct ScopedRecordWriteView<'a> {
    pub version: u32,
    pub profile: &'a str,
    pub source_profile: &'a str,
    pub source_authority_fingerprint: &'a str,
    pub parent_generation: &'a str,
    pub policy_fingerprint: &'a str,
    pub github_user: &'a str,
    pub repo_scope: &'a str,
    pub expires_at: TokenExpiry,
    pub access_token: &'a AccessToken,
}

#[derive(Serialize)]
pub(super) struct RunRecordWriteView<'a> {
    pub version: u32,
    pub run_id: &'a str,
    pub state: RunStateDto,
    pub wrapper_pid: u32,
    pub child_pid: Option<u32>,
    pub command: &'a str,
    pub profile: &'a str,
    pub source_profile: &'a str,
    pub source_authority_fingerprint: &'a str,
    pub github_user: &'a str,
    pub repo_scope: &'a str,
    pub expires_at: TokenExpiry,
    pub access_token: &'a AccessToken,
}

impl<'a> From<&'a BaseCredential> for BaseRecordWriteView<'a> {
    fn from(model: &'a BaseCredential) -> Self {
        Self {
            version: CACHE_SCHEMA_VERSION,
            profile: &model.profile,
            authority_fingerprint: &model.authority_fingerprint,
            github_user: &model.github_user,
            expires_at: model.expires_at,
            access_token: &model.access_token,
        }
    }
}

impl<'a> From<&'a ScopedCredential> for ScopedRecordWriteView<'a> {
    fn from(model: &'a ScopedCredential) -> Self {
        Self {
            version: CACHE_SCHEMA_VERSION,
            profile: &model.profile,
            source_profile: &model.source_profile,
            source_authority_fingerprint: &model.source_authority_fingerprint,
            parent_generation: &model.parent_generation,
            policy_fingerprint: &model.policy_fingerprint,
            github_user: &model.github_user,
            repo_scope: &model.repo_scope,
            expires_at: model.expires_at,
            access_token: &model.access_token,
        }
    }
}

impl<'a> From<&'a RunRecord> for RunRecordWriteView<'a> {
    fn from(model: &'a RunRecord) -> Self {
        Self {
            version: RUN_CACHE_SCHEMA_VERSION,
            run_id: &model.run_id,
            state: model.state.into(),
            wrapper_pid: model.wrapper_pid,
            child_pid: model.child_pid,
            command: &model.command,
            profile: &model.profile,
            source_profile: &model.source_profile,
            source_authority_fingerprint: &model.source_authority_fingerprint,
            github_user: &model.github_user,
            repo_scope: &model.repo_scope,
            expires_at: model.expires_at,
            access_token: &model.access_token,
        }
    }
}

impl<'a> From<&'a Record> for RecordWriteView<'a> {
    fn from(record: &'a Record) -> Self {
        match record {
            Record::Base(entry) => Self::Base(entry.into()),
            Record::Scoped(entry) => Self::Scoped(entry.into()),
            Record::Run(entry) => Self::Run(entry.into()),
        }
    }
}

impl fmt::Debug for RecordWriteView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base(entry) => f.debug_tuple("Base").field(entry).finish(),
            Self::Scoped(entry) => f.debug_tuple("Scoped").field(entry).finish(),
            Self::Run(entry) => f.debug_tuple("Run").field(entry).finish(),
        }
    }
}

impl fmt::Debug for BaseRecordWriteView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BaseRecordWriteView")
            .field("version", &self.version)
            .field("profile", &self.profile)
            .field("authority_fingerprint", &self.authority_fingerprint)
            .field("github_user", &self.github_user)
            .field("expires_at", &self.expires_at)
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for ScopedRecordWriteView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedRecordWriteView")
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
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for RunRecordWriteView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunRecordWriteView")
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
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}
