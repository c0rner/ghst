use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

#[derive(Debug)]
pub enum CacheError {
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidTimestamp(String),
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "cache IO error: {err}"),
            Self::Json(err) => write!(f, "cache JSON error: {err}"),
            Self::InvalidTimestamp(ts) => write!(f, "invalid RFC3339 timestamp '{ts}' in cache"),
        }
    }
}

impl std::error::Error for CacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Json(err) => Some(err),
            Self::InvalidTimestamp(_) => None,
        }
    }
}

/// Compute SHA-256 hex cache key for `profile_name + "|" + canonical_repo_scope`.
pub fn compute_cache_key(profile_name: &str, canonical_repo_scope: &str) -> String {
    use std::fmt::Write;
    let input = format!("{profile_name}|{canonical_repo_scope}");
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    let mut hex = String::with_capacity(result.len() * 2);
    for b in result {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CacheEntry {
    Root(RootCacheEntry),
    Derived(DerivedCacheEntry),
}

impl CacheEntry {
    pub fn profile(&self) -> &str {
        match self {
            Self::Root(r) => &r.profile,
            Self::Derived(d) => &d.profile,
        }
    }

    pub fn github_user(&self) -> &str {
        match self {
            Self::Root(r) => &r.github_user,
            Self::Derived(d) => &d.github_user,
        }
    }

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

/// Ensures that the cache directory exists and has mode `0700` on Unix systems.
pub fn ensure_cache_dir(cache_dir: &Path) -> Result<(), CacheError> {
    if !cache_dir.exists() {
        fs::create_dir_all(cache_dir).map_err(CacheError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(cache_dir, fs::Permissions::from_mode(0o700));
        }
    }
    Ok(())
}

/// Saves a `CacheEntry` to `cache_dir/<hash_key>.json` with mode `0600` on Unix systems.
pub fn save_cache_entry(
    cache_dir: &Path,
    hash_key: &str,
    entry: &CacheEntry,
) -> Result<PathBuf, CacheError> {
    ensure_cache_dir(cache_dir)?;
    let cache_file = cache_dir.join(format!("{hash_key}.json"));
    let json_bytes = serde_json::to_vec_pretty(entry).map_err(CacheError::Json)?;

    fs::write(&cache_file, json_bytes).map_err(CacheError::Io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&cache_file, fs::Permissions::from_mode(0o600));
    }

    Ok(cache_file)
}

/// Loads a `CacheEntry` from `cache_dir/<hash_key>.json`.
pub fn load_cache_entry(
    cache_dir: &Path,
    hash_key: &str,
) -> Result<Option<CacheEntry>, CacheError> {
    let cache_file = cache_dir.join(format!("{hash_key}.json"));
    if !cache_file.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&cache_file).map_err(CacheError::Io)?;
    let entry: CacheEntry = serde_json::from_str(&content).map_err(CacheError::Json)?;
    Ok(Some(entry))
}

/// Deletes a cache entry file `cache_dir/<hash_key>.json`.
pub fn delete_cache_entry(cache_dir: &Path, hash_key: &str) -> Result<bool, CacheError> {
    let cache_file = cache_dir.join(format!("{hash_key}.json"));
    if cache_file.exists() {
        fs::remove_file(&cache_file).map_err(CacheError::Io)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Lists all `(hash_key, CacheEntry)` pairs stored in `cache_dir`.
pub fn list_cache_entries(cache_dir: &Path) -> Result<Vec<(String, CacheEntry)>, CacheError> {
    let mut entries = Vec::new();
    if !cache_dir.exists() {
        return Ok(entries);
    }

    let read_dir = fs::read_dir(cache_dir).map_err(CacheError::Io)?;
    for entry in read_dir {
        let entry = entry.map_err(CacheError::Io)?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(cache_entry) = serde_json::from_str::<CacheEntry>(&content) {
                        entries.push((stem.to_string(), cache_entry));
                    }
                }
            }
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_cache_key() {
        let key1 = compute_cache_key("developer", "all");
        let key2 = compute_cache_key("reader", "c0rner/ghst");
        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 64); // SHA-256 hex output length
    }

    #[test]
    fn test_cache_entry_debug_redaction() {
        let root = CacheEntry::Root(RootCacheEntry {
            profile: "developer".into(),
            github_user: "octocat".into(),
            issued_at: "2026-07-31T18:00:00Z".into(),
            expires_at: "2026-08-01T02:00:00Z".into(),
            access_token: "ghu_secret_123456".into(),
        });

        let debug_str = format!("{root:?}");
        assert!(!debug_str.contains("ghu_secret_123456"));
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[test]
    fn test_timestamp_validation() {
        let future = OffsetDateTime::now_utc() + Duration::hours(1);
        let future_str = format_rfc3339(future);
        assert!(is_timestamp_valid(&future_str));

        let past = OffsetDateTime::now_utc() - Duration::hours(1);
        let past_str = format_rfc3339(past);
        assert!(!is_timestamp_valid(&past_str));
    }
}
