use crate::cache::error::CacheError;
use serde::{Deserialize, Serialize};
use std::fmt;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CacheEntry {
    Root(RootCacheEntry),
    Derived(DerivedCacheEntry),
}

impl CacheEntry {
    #[allow(dead_code)]
    pub fn profile(&self) -> &str {
        match self {
            Self::Root(r) => &r.profile,
            Self::Derived(d) => &d.profile,
        }
    }

    #[allow(dead_code)]
    pub fn github_user(&self) -> &str {
        match self {
            Self::Root(r) => &r.github_user,
            Self::Derived(d) => &d.github_user,
        }
    }

    #[allow(dead_code)]
    pub fn access_token(&self) -> &str {
        match self {
            Self::Root(r) => &r.access_token,
            Self::Derived(d) => &d.access_token,
        }
    }

    pub fn expires_at(&self) -> &str {
        match self {
            Self::Root(r) => &r.expires_at,
            Self::Derived(d) => &d.expires_at,
        }
    }

    pub fn is_valid(&self) -> bool {
        is_timestamp_valid(self.expires_at())
    }

    pub(crate) fn is_expired(&self) -> Result<bool, CacheError> {
        let expiry = OffsetDateTime::parse(self.expires_at(), &Rfc3339)
            .map_err(|_| CacheError::InvalidTimestamp(self.expires_at().to_string()))?;
        Ok(expiry <= OffsetDateTime::now_utc() + Duration::seconds(30))
    }
}

impl fmt::Debug for CacheEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root(r) => f.debug_tuple("Root").field(r).finish(),
            Self::Derived(d) => f.debug_tuple("Derived").field(d).finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootCacheEntry {
    pub profile: String,
    pub github_user: String,
    pub issued_at: String,
    pub expires_at: String,
    pub access_token: String,
}

impl RootCacheEntry {
    pub fn is_valid(&self) -> bool {
        is_timestamp_valid(&self.expires_at)
    }
}

impl fmt::Debug for RootCacheEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootCacheEntry")
            .field("profile", &self.profile)
            .field("github_user", &self.github_user)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedCacheEntry {
    pub profile: String,
    pub source_profile: String,
    pub github_user: String,
    pub repo_scope: String,
    pub issued_at: String,
    pub expires_at: String,
    pub access_token: String,
}

impl fmt::Debug for DerivedCacheEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedCacheEntry")
            .field("profile", &self.profile)
            .field("source_profile", &self.source_profile)
            .field("github_user", &self.github_user)
            .field("repo_scope", &self.repo_scope)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

/// Result of attempting to persist an immutable cache entry.
#[derive(Debug)]
pub enum SaveCacheEntry {
    Saved,
    Retained(CacheEntry),
}

/// Formats an `OffsetDateTime` as an RFC 3339 timestamp string.
pub fn format_rfc3339(dt: OffsetDateTime) -> String {
    dt.format(&Rfc3339).unwrap_or_default()
}

/// Checks if an RFC 3339 timestamp is in the future (with a 30-second safety margin).
pub fn is_timestamp_valid(expires_at_str: &str) -> bool {
    OffsetDateTime::parse(expires_at_str, &Rfc3339).is_ok_and(|expires_at| {
        let now = OffsetDateTime::now_utc();
        expires_at > now + Duration::seconds(30)
    })
}
