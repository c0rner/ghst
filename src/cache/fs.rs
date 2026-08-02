use crate::cache::error::CacheError;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

const CACHE_LOCK_FILE: &str = ".cache.lock";

#[derive(Clone, Copy)]
pub enum LockMode {
    Shared,
    Exclusive,
}

/// Ensures that the cache directory exists and has private permissions.
pub fn ensure_cache_dir(cache_dir: &Path) -> Result<(), CacheError> {
    #[cfg(not(unix))]
    return Err(unsupported_platform(cache_dir));

    #[cfg(unix)]
    match fs::symlink_metadata(cache_dir) {
        Ok(metadata) => {
            validate_cache_dir(cache_dir, &metadata)?;
            validate_cache_dir_openable(cache_dir)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            create_private_cache_dir(cache_dir)?;
            let metadata = fs::symlink_metadata(cache_dir).map_err(CacheError::Io)?;
            validate_cache_dir(cache_dir, &metadata)?;
            validate_cache_dir_openable(cache_dir)
        }
        Err(err) => Err(CacheError::Io(err)),
    }
}

pub fn cache_dir_exists(cache_dir: &Path) -> Result<bool, CacheError> {
    #[cfg(not(unix))]
    return Err(unsupported_platform(cache_dir));

    #[cfg(unix)]
    match fs::symlink_metadata(cache_dir) {
        Ok(metadata) => {
            validate_cache_dir(cache_dir, &metadata)?;
            validate_cache_dir_openable(cache_dir)?;
            Ok(true)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(CacheError::Io(err)),
    }
}

pub fn cache_file_path(cache_dir: &Path, hash_key: &str) -> PathBuf {
    cache_dir.join(format!("{hash_key}.json"))
}

pub fn with_cache_lock<T>(
    cache_dir: &Path,
    lock_mode: LockMode,
    operation: impl FnOnce() -> Result<T, CacheError>,
) -> Result<T, CacheError> {
    ensure_cache_dir(cache_dir)?;

    let lock_file = open_cache_lock_file(cache_dir)?;
    match lock_mode {
        LockMode::Shared => fs2::FileExt::lock_shared(&lock_file).map_err(CacheError::Io)?,
        LockMode::Exclusive => fs2::FileExt::lock_exclusive(&lock_file).map_err(CacheError::Io)?,
    }

    operation()
}

pub fn create_private_tempfile(cache_dir: &Path) -> Result<tempfile::NamedTempFile, CacheError> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(".ghst-").suffix(".tmp");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        builder.permissions(fs::Permissions::from_mode(0o600));
    }

    builder.tempfile_in(cache_dir).map_err(CacheError::Io)
}

pub fn open_private_file(path: &Path, create: bool) -> Result<File, CacheError> {
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

pub fn validate_cache_file(path: &Path, metadata: &fs::Metadata) -> Result<(), CacheError> {
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

pub fn sync_cache_dir(cache_dir: &Path) -> Result<(), CacheError> {
    #[cfg(not(unix))]
    return Err(unsupported_platform(cache_dir));

    #[cfg(unix)]
    open_validated_cache_dir(cache_dir)?
        .sync_all()
        .map_err(CacheError::Io)
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

fn open_cache_lock_file(cache_dir: &Path) -> Result<File, CacheError> {
    let lock_path = cache_dir.join(CACHE_LOCK_FILE);
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

fn validate_cache_dir(path: &Path, metadata: &fs::Metadata) -> Result<(), CacheError> {
    if metadata.file_type().is_symlink() {
        return Err(insecure_path(path, "symbolic links are not permitted"));
    }
    if !metadata.is_dir() {
        return Err(insecure_path(path, "expected a directory"));
    }

    validate_unix_metadata(path, metadata, 0o700)
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
fn open_validated_cache_dir(cache_dir: &Path) -> Result<File, CacheError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.read(true).custom_flags(open_flags(
        rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW,
    )?);
    let directory = options.open(cache_dir).map_err(CacheError::Io)?;
    let metadata = directory.metadata().map_err(CacheError::Io)?;
    validate_cache_dir(cache_dir, &metadata)?;
    Ok(directory)
}

#[cfg(unix)]
fn validate_cache_dir_openable(cache_dir: &Path) -> Result<(), CacheError> {
    open_validated_cache_dir(cache_dir).map(|_| ())
}

#[cfg(not(unix))]
fn validate_open_cache_dir(cache_dir: &Path) -> Result<(), CacheError> {
    Err(unsupported_platform(cache_dir))
}

#[cfg(unix)]
fn open_flags(flags: rustix::fs::OFlags) -> Result<i32, CacheError> {
    i32::try_from(flags.bits())
        .map_err(|_| CacheError::Platform("required filesystem open flags are not supported"))
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
