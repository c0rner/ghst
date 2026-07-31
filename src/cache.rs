use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

#[derive(Debug)]
pub enum CacheError {
    Io(std::io::Error),
    Json(serde_json::Error),
    InsecurePath { path: PathBuf, reason: &'static str },
    InvalidKey(String),
    InvalidTimestamp(String),
    Platform(&'static str),
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "cache IO error: {err}"),
            Self::Json(err) => write!(f, "cache JSON error: {err}"),
            Self::InsecurePath { path, reason } => {
                write!(f, "insecure cache path '{}': {reason}", path.display())
            }
            Self::InvalidKey(key) => write!(f, "invalid cache key '{key}'"),
            Self::InvalidTimestamp(timestamp) => {
                write!(f, "invalid RFC3339 expiry timestamp '{timestamp}' in cache")
            }
            Self::Platform(reason) => write!(f, "cache platform error: {reason}"),
        }
    }
}

impl std::error::Error for CacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Json(err) => Some(err),
            Self::InsecurePath { .. }
            | Self::InvalidKey(_)
            | Self::InvalidTimestamp(_)
            | Self::Platform(_) => None,
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

    fn is_expired(&self) -> Result<bool, CacheError> {
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

/// Ensures that the cache directory exists and has private permissions.
pub fn ensure_cache_dir(cache_dir: &Path) -> Result<(), CacheError> {
    #[cfg(not(unix))]
    return Err(unsupported_platform(cache_dir));

    match fs::symlink_metadata(cache_dir) {
        Ok(metadata) => {
            validate_cache_dir(cache_dir, &metadata)?;
            validate_open_cache_dir(cache_dir)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            create_private_cache_dir(cache_dir)?;
            let metadata = fs::symlink_metadata(cache_dir).map_err(CacheError::Io)?;
            validate_cache_dir(cache_dir, &metadata)?;
            validate_open_cache_dir(cache_dir)
        }
        Err(err) => Err(CacheError::Io(err)),
    }
}

/// Result of attempting to persist an immutable cache entry.
#[derive(Debug)]
pub enum SaveCacheEntry {
    Saved,
    Retained(CacheEntry),
}

/// Saves a `CacheEntry` to `cache_dir/<hash_key>.json`.
///
/// A valid existing entry is retained. An expired entry is atomically replaced.
pub fn save_cache_entry(
    cache_dir: &Path,
    hash_key: &str,
    entry: &CacheEntry,
) -> Result<SaveCacheEntry, CacheError> {
    ensure_cache_dir(cache_dir)?;
    let json_bytes = serde_json::to_vec_pretty(entry).map_err(CacheError::Json)?;

    with_cache_lock(cache_dir, hash_key, LockMode::Exclusive, |cache_file| {
        if let Some(existing) = read_cache_entry(cache_file)? {
            if !existing.is_expired()? {
                return Ok(SaveCacheEntry::Retained(existing));
            }
        }

        let mut temporary = create_private_tempfile(cache_dir)?;
        temporary
            .as_file_mut()
            .write_all(&json_bytes)
            .map_err(CacheError::Io)?;
        temporary.as_file_mut().sync_all().map_err(CacheError::Io)?;
        temporary
            .persist(cache_file)
            .map_err(|err| CacheError::Io(err.error))?;
        sync_cache_dir(cache_dir)?;

        let metadata = fs::symlink_metadata(cache_file).map_err(CacheError::Io)?;
        validate_cache_file(cache_file, &metadata)?;

        Ok(SaveCacheEntry::Saved)
    })
}

/// Loads a `CacheEntry` from `cache_dir/<hash_key>.json`.
pub fn load_cache_entry(
    cache_dir: &Path,
    hash_key: &str,
) -> Result<Option<CacheEntry>, CacheError> {
    if !cache_dir_exists(cache_dir)? {
        return Ok(None);
    }

    with_cache_lock(cache_dir, hash_key, LockMode::Shared, read_cache_entry)
}

/// Deletes a cache entry file `cache_dir/<hash_key>.json`.
pub fn delete_cache_entry(cache_dir: &Path, hash_key: &str) -> Result<bool, CacheError> {
    if !cache_dir_exists(cache_dir)? {
        return Ok(false);
    }

    with_cache_lock(cache_dir, hash_key, LockMode::Exclusive, |cache_file| {
        match fs::symlink_metadata(cache_file) {
            Ok(metadata) => {
                validate_cache_file(cache_file, &metadata)?;
                fs::remove_file(cache_file).map_err(CacheError::Io)?;
                Ok(true)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(CacheError::Io(err)),
        }
    })
}

/// Lists all `(hash_key, CacheEntry)` pairs stored in `cache_dir`.
pub fn list_cache_entries(cache_dir: &Path) -> Result<Vec<(String, CacheEntry)>, CacheError> {
    let mut entries = Vec::new();
    if !cache_dir_exists(cache_dir)? {
        return Ok(entries);
    }

    let read_dir = fs::read_dir(cache_dir).map_err(CacheError::Io)?;
    for entry in read_dir {
        let entry = entry.map_err(CacheError::Io)?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }

        let hash_key = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| CacheError::InsecurePath {
                path: path.clone(),
                reason: "cache entry name is not valid UTF-8",
            })?;
        validate_cache_key(hash_key)?;

        if let Some(cache_entry) =
            with_cache_lock(cache_dir, hash_key, LockMode::Shared, read_cache_entry)?
        {
            entries.push((hash_key.to_string(), cache_entry));
        }
    }

    Ok(entries)
}

#[derive(Clone, Copy)]
enum LockMode {
    Shared,
    Exclusive,
}

fn cache_dir_exists(cache_dir: &Path) -> Result<bool, CacheError> {
    #[cfg(not(unix))]
    return Err(unsupported_platform(cache_dir));

    match fs::symlink_metadata(cache_dir) {
        Ok(metadata) => {
            validate_cache_dir(cache_dir, &metadata)?;
            validate_open_cache_dir(cache_dir)?;
            Ok(true)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(CacheError::Io(err)),
    }
}

fn create_private_cache_dir(cache_dir: &Path) -> Result<(), CacheError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.recursive(true);
        match builder.create(cache_dir) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(err) => Err(CacheError::Io(err)),
        }
    }

    #[cfg(not(unix))]
    {
        Err(unsupported_platform(cache_dir))
    }
}

fn with_cache_lock<T>(
    cache_dir: &Path,
    hash_key: &str,
    lock_mode: LockMode,
    operation: impl FnOnce(&Path) -> Result<T, CacheError>,
) -> Result<T, CacheError> {
    ensure_cache_dir(cache_dir)?;
    validate_cache_key(hash_key)?;

    let lock_file = open_lock_file(cache_dir, hash_key)?;
    match lock_mode {
        LockMode::Shared => fs2::FileExt::lock_shared(&lock_file).map_err(CacheError::Io)?,
        LockMode::Exclusive => fs2::FileExt::lock_exclusive(&lock_file).map_err(CacheError::Io)?,
    }

    operation(&cache_file_path(cache_dir, hash_key))
}

fn open_lock_file(cache_dir: &Path, hash_key: &str) -> Result<File, CacheError> {
    let lock_path = cache_dir.join(format!("{hash_key}.lock"));
    match fs::symlink_metadata(&lock_path) {
        Ok(metadata) => validate_cache_file(&lock_path, &metadata)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(CacheError::Io(err)),
    }

    let file = open_private_file(&lock_path, true)?;
    let metadata = file.metadata().map_err(CacheError::Io)?;
    validate_cache_file(&lock_path, &metadata)?;
    Ok(file)
}

fn read_cache_entry(cache_file: &Path) -> Result<Option<CacheEntry>, CacheError> {
    match fs::symlink_metadata(cache_file) {
        Ok(metadata) => {
            validate_cache_file(cache_file, &metadata)?;
            let mut content = String::new();
            open_private_file(cache_file, false)?
                .read_to_string(&mut content)
                .map_err(CacheError::Io)?;
            serde_json::from_str(&content)
                .map(Some)
                .map_err(CacheError::Json)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(CacheError::Io(err)),
    }
}

fn create_private_tempfile(cache_dir: &Path) -> Result<tempfile::NamedTempFile, CacheError> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(".ghst-").suffix(".tmp");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        builder.permissions(fs::Permissions::from_mode(0o600));
    }

    builder.tempfile_in(cache_dir).map_err(CacheError::Io)
}

fn open_private_file(path: &Path, create: bool) -> Result<File, CacheError> {
    let mut options = OpenOptions::new();
    options.read(true).write(create).create(create);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options
            .mode(0o600)
            .custom_flags(open_flags(rustix::fs::OFlags::NOFOLLOW)?);
    }

    options.open(path).map_err(CacheError::Io)
}

#[cfg(unix)]
fn open_flags(flags: rustix::fs::OFlags) -> Result<i32, CacheError> {
    i32::try_from(flags.bits())
        .map_err(|_| CacheError::Platform("required filesystem open flags are not supported"))
}

fn cache_file_path(cache_dir: &Path, hash_key: &str) -> PathBuf {
    cache_dir.join(format!("{hash_key}.json"))
}

fn validate_cache_key(hash_key: &str) -> Result<(), CacheError> {
    if hash_key.len() == 64 && hash_key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(CacheError::InvalidKey(hash_key.to_string()))
    }
}

fn validate_cache_dir(path: &Path, metadata: &fs::Metadata) -> Result<(), CacheError> {
    if metadata.file_type().is_symlink() {
        return Err(insecure_path(path, "symbolic links are not permitted"));
    }
    if !metadata.is_dir() {
        return Err(insecure_path(path, "expected a directory"));
    }

    validate_unix_metadata(path, metadata, 0o700)
}

fn validate_cache_file(path: &Path, metadata: &fs::Metadata) -> Result<(), CacheError> {
    if metadata.file_type().is_symlink() {
        return Err(insecure_path(path, "symbolic links are not permitted"));
    }
    if !metadata.is_file() {
        return Err(insecure_path(path, "expected a regular file"));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.nlink() != 1 {
            return Err(insecure_path(path, "hard links are not permitted"));
        }
    }

    validate_unix_metadata(path, metadata, 0o600)
}

#[cfg(unix)]
fn validate_unix_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    expected_mode: u32,
) -> Result<(), CacheError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(insecure_path(path, "not owned by the effective user"));
    }
    if metadata.permissions().mode() & 0o7777 != expected_mode {
        return Err(insecure_path(path, "unexpected permissions"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_unix_metadata(
    path: &Path,
    _metadata: &fs::Metadata,
    _expected_mode: u32,
) -> Result<(), CacheError> {
    Err(unsupported_platform(path))
}

#[cfg(unix)]
fn validate_open_cache_dir(cache_dir: &Path) -> Result<(), CacheError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.read(true).custom_flags(open_flags(
        rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW,
    )?);
    let directory = options.open(cache_dir).map_err(CacheError::Io)?;
    let metadata = directory.metadata().map_err(CacheError::Io)?;
    validate_cache_dir(cache_dir, &metadata)
}

#[cfg(not(unix))]
fn validate_open_cache_dir(cache_dir: &Path) -> Result<(), CacheError> {
    Err(unsupported_platform(cache_dir))
}

#[cfg(unix)]
fn sync_cache_dir(cache_dir: &Path) -> Result<(), CacheError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.read(true).custom_flags(open_flags(
        rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW,
    )?);
    let directory = options.open(cache_dir).map_err(CacheError::Io)?;
    let metadata = directory.metadata().map_err(CacheError::Io)?;
    validate_cache_dir(cache_dir, &metadata)?;
    directory.sync_all().map_err(CacheError::Io)
}

#[cfg(not(unix))]
fn sync_cache_dir(cache_dir: &Path) -> Result<(), CacheError> {
    Err(unsupported_platform(cache_dir))
}

#[cfg(not(unix))]
fn unsupported_platform(_path: &Path) -> CacheError {
    CacheError::Platform("secure token cache storage is not supported on this platform")
}

fn insecure_path(path: &Path, reason: &'static str) -> CacheError {
    CacheError::InsecurePath {
        path: path.to_path_buf(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    const TEST_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn test_entry(access_token: &str, expires_at: OffsetDateTime) -> CacheEntry {
        CacheEntry::Root(RootCacheEntry {
            profile: "developer".into(),
            github_user: "octocat".into(),
            issued_at: format_rfc3339(OffsetDateTime::now_utc()),
            expires_at: format_rfc3339(expires_at),
            access_token: access_token.into(),
        })
    }

    fn test_cache_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

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

    #[test]
    fn test_save_creates_private_cache_directory_and_entry() {
        let temp_dir = test_cache_dir();
        let cache_dir = temp_dir.path().join("cache");
        let entry = test_entry(
            "first-token",
            OffsetDateTime::now_utc() + Duration::hours(1),
        );

        assert!(matches!(
            save_cache_entry(&cache_dir, TEST_KEY, &entry).unwrap(),
            SaveCacheEntry::Saved
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(&cache_dir).unwrap().permissions().mode() & 0o7777,
                0o700
            );
            assert_eq!(
                fs::metadata(cache_file_path(&cache_dir, TEST_KEY))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o600
            );
            assert_eq!(
                fs::metadata(cache_dir.join(format!("{TEST_KEY}.lock")))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o600
            );
        }
    }

    #[test]
    fn test_save_creates_missing_cache_parents() {
        let temp_dir = test_cache_dir();
        let cache_dir = temp_dir.path().join("missing-parent").join("cache");
        let entry = test_entry(
            "first-token",
            OffsetDateTime::now_utc() + Duration::hours(1),
        );

        assert!(matches!(
            save_cache_entry(&cache_dir, TEST_KEY, &entry).unwrap(),
            SaveCacheEntry::Saved
        ));
        assert!(cache_dir.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn test_save_rejects_insecure_existing_cache_directory() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = test_cache_dir();
        let cache_dir = temp_dir.path().join("cache");
        fs::create_dir(&cache_dir).unwrap();
        fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o755)).unwrap();

        let entry = test_entry(
            "first-token",
            OffsetDateTime::now_utc() + Duration::hours(1),
        );
        let error = save_cache_entry(&cache_dir, TEST_KEY, &entry).unwrap_err();

        assert!(matches!(
            error,
            CacheError::InsecurePath {
                reason: "unexpected permissions",
                ..
            }
        ));
        assert_eq!(
            fs::metadata(&cache_dir).unwrap().permissions().mode() & 0o7777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_cache_rejects_symlinked_directory_and_entry() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp_dir = test_cache_dir();
        let target_dir = temp_dir.path().join("target");
        fs::create_dir(&target_dir).unwrap();
        fs::set_permissions(&target_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let cache_symlink = temp_dir.path().join("cache-link");
        symlink(&target_dir, &cache_symlink).unwrap();

        assert!(matches!(
            ensure_cache_dir(&cache_symlink),
            Err(CacheError::InsecurePath {
                reason: "symbolic links are not permitted",
                ..
            })
        ));

        let cache_dir = temp_dir.path().join("cache");
        ensure_cache_dir(&cache_dir).unwrap();
        let target_file = temp_dir.path().join("target.json");
        fs::write(&target_file, "target content").unwrap();
        fs::set_permissions(&target_file, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target_file, cache_file_path(&cache_dir, TEST_KEY)).unwrap();

        assert!(matches!(
            load_cache_entry(&cache_dir, TEST_KEY),
            Err(CacheError::InsecurePath {
                reason: "symbolic links are not permitted",
                ..
            })
        ));
        assert_eq!(fs::read_to_string(target_file).unwrap(), "target content");
    }

    #[cfg(unix)]
    #[test]
    fn test_cache_rejects_insecure_entry_without_modifying_it() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = test_cache_dir();
        let cache_dir = temp_dir.path().join("cache");
        ensure_cache_dir(&cache_dir).unwrap();
        let cache_file = cache_file_path(&cache_dir, TEST_KEY);
        let original = "{\"not\":\"a cache entry\"}";
        fs::write(&cache_file, original).unwrap();
        fs::set_permissions(&cache_file, fs::Permissions::from_mode(0o644)).unwrap();

        let entry = test_entry(
            "replacement",
            OffsetDateTime::now_utc() + Duration::hours(1),
        );
        assert!(matches!(
            save_cache_entry(&cache_dir, TEST_KEY, &entry),
            Err(CacheError::InsecurePath {
                reason: "unexpected permissions",
                ..
            })
        ));
        assert_eq!(fs::read_to_string(cache_file).unwrap(), original);
    }

    #[test]
    fn test_cache_rejects_non_regular_entry() {
        let temp_dir = test_cache_dir();
        let cache_dir = temp_dir.path().join("cache");
        ensure_cache_dir(&cache_dir).unwrap();
        fs::create_dir(cache_file_path(&cache_dir, TEST_KEY)).unwrap();

        assert!(matches!(
            load_cache_entry(&cache_dir, TEST_KEY),
            Err(CacheError::InsecurePath {
                reason: "expected a regular file",
                ..
            })
        ));
    }

    #[test]
    fn test_valid_entry_is_retained_and_expired_entry_is_replaced() {
        let temp_dir = test_cache_dir();
        let cache_dir = temp_dir.path().join("cache");
        let valid = test_entry(
            "original-token",
            OffsetDateTime::now_utc() + Duration::hours(1),
        );
        let replacement = test_entry(
            "replacement-token",
            OffsetDateTime::now_utc() + Duration::hours(2),
        );

        assert!(matches!(
            save_cache_entry(&cache_dir, TEST_KEY, &valid).unwrap(),
            SaveCacheEntry::Saved
        ));
        let retained = save_cache_entry(&cache_dir, TEST_KEY, &replacement).unwrap();
        assert!(matches!(
            retained,
            SaveCacheEntry::Retained(CacheEntry::Root(RootCacheEntry { access_token, .. }))
                if access_token == "original-token"
        ));

        let expired_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let expired = test_entry(
            "expired-token",
            OffsetDateTime::now_utc() - Duration::hours(1),
        );
        assert!(matches!(
            save_cache_entry(&cache_dir, expired_key, &expired).unwrap(),
            SaveCacheEntry::Saved
        ));
        assert!(matches!(
            save_cache_entry(&cache_dir, expired_key, &replacement).unwrap(),
            SaveCacheEntry::Saved
        ));
        assert!(matches!(
            load_cache_entry(&cache_dir, expired_key).unwrap(),
            Some(CacheEntry::Root(RootCacheEntry { access_token, .. }))
                if access_token == "replacement-token"
        ));
    }

    #[test]
    fn test_malformed_entry_is_retained_and_reported() {
        let temp_dir = test_cache_dir();
        let cache_dir = temp_dir.path().join("cache");
        ensure_cache_dir(&cache_dir).unwrap();
        let cache_file = cache_file_path(&cache_dir, TEST_KEY);
        let original = "{ malformed";
        let mut file = create_private_tempfile(&cache_dir).unwrap();
        file.write_all(original.as_bytes()).unwrap();
        file.persist(&cache_file).unwrap();

        let entry = test_entry(
            "replacement",
            OffsetDateTime::now_utc() + Duration::hours(1),
        );
        assert!(matches!(
            save_cache_entry(&cache_dir, TEST_KEY, &entry),
            Err(CacheError::Json(_))
        ));
        assert_eq!(fs::read_to_string(cache_file).unwrap(), original);
    }

    #[test]
    fn test_invalid_expiry_is_retained_and_reported() {
        let temp_dir = test_cache_dir();
        let cache_dir = temp_dir.path().join("cache");
        ensure_cache_dir(&cache_dir).unwrap();
        let cache_file = cache_file_path(&cache_dir, TEST_KEY);
        let invalid_expiry = CacheEntry::Root(RootCacheEntry {
            profile: "developer".into(),
            github_user: "octocat".into(),
            issued_at: format_rfc3339(OffsetDateTime::now_utc()),
            expires_at: "not-a-timestamp".into(),
            access_token: "existing-token".into(),
        });
        let original = serde_json::to_string(&invalid_expiry).unwrap();
        let mut file = create_private_tempfile(&cache_dir).unwrap();
        file.write_all(original.as_bytes()).unwrap();
        file.persist(&cache_file).unwrap();

        let replacement = test_entry(
            "replacement-token",
            OffsetDateTime::now_utc() + Duration::hours(1),
        );
        assert!(matches!(
            save_cache_entry(&cache_dir, TEST_KEY, &replacement),
            Err(CacheError::InvalidTimestamp(timestamp)) if timestamp == "not-a-timestamp"
        ));
        assert_eq!(fs::read_to_string(cache_file).unwrap(), original);
    }

    #[test]
    fn test_concurrent_saves_preserve_one_valid_entry() {
        let temp_dir = test_cache_dir();
        let cache_dir = Arc::new(temp_dir.path().join("cache"));
        let barrier = Arc::new(Barrier::new(2));
        let first_entry = test_entry(
            "first-token",
            OffsetDateTime::now_utc() + Duration::hours(1),
        );
        let second_entry = test_entry(
            "second-token",
            OffsetDateTime::now_utc() + Duration::hours(1),
        );

        let first = {
            let cache_dir = Arc::clone(&cache_dir);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                save_cache_entry(&cache_dir, TEST_KEY, &first_entry).unwrap()
            })
        };
        let second = {
            let cache_dir = Arc::clone(&cache_dir);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                save_cache_entry(&cache_dir, TEST_KEY, &second_entry).unwrap()
            })
        };

        let results = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, SaveCacheEntry::Saved))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, SaveCacheEntry::Retained(_)))
                .count(),
            1
        );

        let content = fs::read_to_string(cache_file_path(&cache_dir, TEST_KEY)).unwrap();
        let entry: CacheEntry = serde_json::from_str(&content).unwrap();
        assert!(matches!(
            entry,
            CacheEntry::Root(RootCacheEntry { access_token, .. })
                if access_token == "first-token" || access_token == "second-token"
        ));
    }

    #[test]
    fn test_delete_and_list_use_validated_cache_entries() {
        let temp_dir = test_cache_dir();
        let cache_dir = temp_dir.path().join("cache");
        let entry = test_entry(
            "first-token",
            OffsetDateTime::now_utc() + Duration::hours(1),
        );
        save_cache_entry(&cache_dir, TEST_KEY, &entry).unwrap();

        assert_eq!(list_cache_entries(&cache_dir).unwrap().len(), 1);
        assert!(delete_cache_entry(&cache_dir, TEST_KEY).unwrap());
        assert!(list_cache_entries(&cache_dir).unwrap().is_empty());
    }
}
