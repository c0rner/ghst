use super::digest::encode_hex;
use crate::credential::provenance::ScopedProvenance;
use crate::credential::{AccessToken, TokenExpiry};
use crate::run::lifecycle::{RunLifecycle, RunOwner, RunPhase};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use time::OffsetDateTime;

#[derive(PartialEq, Eq)]
pub enum StoredCredential {
    Base(StoredBase),
    Scoped(StoredScoped),
    Run(StoredRun),
}

impl StoredCredential {
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

    pub const fn access_token(&self) -> &AccessToken {
        match self {
            Self::Base(entry) => &entry.access_token,
            Self::Scoped(entry) => &entry.access_token,
            Self::Run(entry) => &entry.access_token,
        }
    }

    pub fn is_safe_to_handoff_at(&self, now: OffsetDateTime) -> bool {
        match self {
            Self::Base(entry) => entry.expires_at.is_safe_to_handoff_at(now),
            Self::Scoped(entry) => entry.expires_at.is_safe_to_handoff_at(now),
            Self::Run(entry) => entry.expires_at.is_safe_to_handoff_at(now),
        }
    }
}

impl fmt::Debug for StoredCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base(entry) => f.debug_tuple("Base").field(entry).finish(),
            Self::Scoped(entry) => f.debug_tuple("Scoped").field(entry).finish(),
            Self::Run(entry) => f.debug_tuple("Run").field(entry).finish(),
        }
    }
}

#[derive(PartialEq, Eq)]
pub struct StoredBase {
    pub profile: String,
    pub authority_fingerprint: String,
    pub github_user: String,
    pub expires_at: TokenExpiry,
    pub access_token: AccessToken,
}

impl StoredBase {
    pub fn generation_fingerprint(&self) -> String {
        generation_fingerprint(&self.access_token)
    }
}

impl fmt::Debug for StoredBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredBase")
            .field("profile", &self.profile)
            .field("authority_fingerprint", &self.authority_fingerprint)
            .field("github_user", &self.github_user)
            .field("expires_at", &self.expires_at)
            .field("access_token", &self.access_token)
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub struct StoredScoped {
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

impl StoredScoped {
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

#[derive(PartialEq, Eq)]
pub struct StoredRun {
    pub run_id: String,
    pub phase: RunPhase,
    pub wrapper_pid: u32,
    pub command: String,
    pub profile: String,
    pub source_profile: String,
    pub source_authority_fingerprint: String,
    pub github_user: String,
    pub repo_scope: String,
    pub expires_at: TokenExpiry,
    pub access_token: AccessToken,
}

impl StoredRun {
    pub fn lifecycle(&self) -> RunLifecycle<'_> {
        RunLifecycle::new(
            RunOwner {
                run_id: &self.run_id,
                wrapper_pid: self.wrapper_pid,
            },
            self.phase,
        )
    }
    pub const fn child_pid(&self) -> Option<u32> {
        match self.phase {
            RunPhase::Pending => None,
            RunPhase::Running { child_pid } => Some(child_pid),
            RunPhase::CleanupPending { child_pid } => child_pid,
        }
    }
}

impl fmt::Debug for StoredRun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredRun")
            .field("run_id", &self.run_id)
            .field("phase", &self.phase)
            .field("wrapper_pid", &self.wrapper_pid)
            .field("child_pid", &self.child_pid())
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

impl fmt::Debug for StoredScoped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredScoped")
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

/// Compute SHA-256 hex cache key for `profile_name + "|" + canonical_repo_scope`.
pub fn compute_cache_key(profile_name: &str, canonical_repo_scope: &str) -> String {
    let input = format!("{profile_name}|{canonical_repo_scope}");
    let digest = Sha256::digest(input.as_bytes());
    encode_hex(&digest)
}

/// Compute a domain-separated SHA-256 cache key for a one-off run identifier.
pub fn compute_run_cache_key(run_id: &str) -> String {
    let mut hasher = Sha256::new();
    for part in ["ghst-cache-key-v1", "run", run_id] {
        hasher.update(part.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(part.as_bytes());
    }
    encode_hex(&hasher.finalize())
}

pub fn generation_fingerprint(token: &AccessToken) -> String {
    fingerprint(&[token.as_ref()])
}
