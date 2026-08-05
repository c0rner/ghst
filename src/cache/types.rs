use crate::cache::digest::encode_hex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

pub const CACHE_SCHEMA_VERSION: u32 = 2;
pub const TOKEN_SAFETY_MARGIN: Duration = Duration::seconds(30);

/// A secret access token that is zeroized on drop and never exposed by `Debug`.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccessToken(Zeroizing<String>);

impl AccessToken {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl AsRef<str> for AccessToken {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl From<String> for AccessToken {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for AccessToken {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// A parsed RFC 3339 token expiration timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TokenExpiry(OffsetDateTime);

impl TokenExpiry {
    pub const fn new(value: OffsetDateTime) -> Self {
        Self(value)
    }

    pub const fn value(self) -> OffsetDateTime {
        self.0
    }

    pub fn parse(value: &str) -> Result<Self, time::error::Parse> {
        OffsetDateTime::parse(value, &Rfc3339).map(Self)
    }

    pub fn is_usable_at(self, now: OffsetDateTime) -> bool {
        self.0 > now + TOKEN_SAFETY_MARGIN
    }
}

impl fmt::Display for TokenExpiry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.0.format(&Rfc3339).map_err(|_| fmt::Error)?;
        f.write_str(&value)
    }
}

impl Serialize for TokenExpiry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for TokenExpiry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(PartialEq, Eq)]
pub enum CacheEntry {
    Root(RootCacheEntry),
    Derived(DerivedCacheEntry),
}

impl CacheEntry {
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Root(_) => "root",
            Self::Derived(_) => "derived",
        }
    }

    pub fn profile(&self) -> &str {
        match self {
            Self::Root(entry) => &entry.profile,
            Self::Derived(entry) => &entry.profile,
        }
    }

    pub fn repo_scope(&self) -> &str {
        match self {
            Self::Root(_) => "all",
            Self::Derived(entry) => &entry.repo_scope,
        }
    }

    pub const fn access_token(&self) -> &AccessToken {
        match self {
            Self::Root(entry) => &entry.access_token,
            Self::Derived(entry) => &entry.access_token,
        }
    }

    pub const fn is_current(&self) -> bool {
        match self {
            Self::Root(entry) => entry.version == CACHE_SCHEMA_VERSION,
            Self::Derived(entry) => entry.version == CACHE_SCHEMA_VERSION,
        }
    }

    pub fn is_usable_at(&self, now: OffsetDateTime) -> bool {
        match self {
            Self::Root(entry) => entry.expires_at.is_usable_at(now),
            Self::Derived(entry) => entry.expires_at.is_usable_at(now),
        }
    }

    pub fn compatible_with(&self, candidate: &Self, now: OffsetDateTime) -> bool {
        if !self.is_current() || !self.is_usable_at(now) {
            return false;
        }

        match (self, candidate) {
            (Self::Root(existing), Self::Root(candidate)) => {
                existing.profile == candidate.profile
                    && existing.authority_fingerprint == candidate.authority_fingerprint
            }
            (Self::Derived(existing), Self::Derived(candidate)) => {
                existing.profile == candidate.profile
                    && existing.source_profile == candidate.source_profile
                    && existing.repo_scope == candidate.repo_scope
                    && existing.parent_generation == candidate.parent_generation
                    && existing.policy_fingerprint == candidate.policy_fingerprint
            }
            _ => false,
        }
    }

    pub const fn as_root(&self) -> Option<&RootCacheEntry> {
        match self {
            Self::Root(entry) => Some(entry),
            Self::Derived(_) => None,
        }
    }

    pub const fn as_derived(&self) -> Option<&DerivedCacheEntry> {
        match self {
            Self::Derived(entry) => Some(entry),
            Self::Root(_) => None,
        }
    }
}

impl fmt::Debug for CacheEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root(entry) => f.debug_tuple("Root").field(entry).finish(),
            Self::Derived(entry) => f.debug_tuple("Derived").field(entry).finish(),
        }
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCacheEntry {
    pub version: u32,
    pub profile: String,
    pub authority_fingerprint: String,
    pub github_user: String,
    pub issued_at: String,
    pub expires_at: TokenExpiry,
    pub access_token: AccessToken,
}

impl RootCacheEntry {
    pub fn generation_fingerprint(&self) -> String {
        fingerprint(&[self.access_token.as_ref()])
    }
}

impl fmt::Debug for RootCacheEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootCacheEntry")
            .field("version", &self.version)
            .field("profile", &self.profile)
            .field("authority_fingerprint", &self.authority_fingerprint)
            .field("github_user", &self.github_user)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("access_token", &self.access_token)
            .finish()
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedCacheEntry {
    pub version: u32,
    pub profile: String,
    pub source_profile: String,
    pub parent_generation: String,
    pub policy_fingerprint: String,
    pub github_user: String,
    pub repo_scope: String,
    pub issued_at: String,
    pub expires_at: TokenExpiry,
    pub access_token: AccessToken,
}

impl fmt::Debug for DerivedCacheEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedCacheEntry")
            .field("version", &self.version)
            .field("profile", &self.profile)
            .field("source_profile", &self.source_profile)
            .field("parent_generation", &self.parent_generation)
            .field("policy_fingerprint", &self.policy_fingerprint)
            .field("github_user", &self.github_user)
            .field("repo_scope", &self.repo_scope)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("access_token", &self.access_token)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CurrentCacheEntryRef<'a> {
    Root(&'a RootCacheEntry),
    Derived(&'a DerivedCacheEntry),
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CurrentCacheEntry {
    Root(RootCacheEntry),
    Derived(DerivedCacheEntry),
}

impl Serialize for CacheEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Root(entry) => CurrentCacheEntryRef::Root(entry).serialize(serializer),
            Self::Derived(entry) => CurrentCacheEntryRef::Derived(entry).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for CacheEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match CurrentCacheEntry::deserialize(deserializer)? {
            CurrentCacheEntry::Root(entry) => Ok(Self::Root(entry)),
            CurrentCacheEntry::Derived(entry) => Ok(Self::Derived(entry)),
        }
    }
}

/// Result of attempting to persist an immutable cache entry.
#[derive(Debug)]
pub enum SaveCacheEntry {
    Saved,
    Retained(Box<CacheEntry>),
}

pub fn format_rfc3339(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_default()
}

pub fn authority_fingerprint(client_id: &str, account: &str) -> String {
    fingerprint(&[client_id, account])
}

pub fn policy_fingerprint(
    account: &str,
    repo_scope: &str,
    permissions: &BTreeMap<String, String>,
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
