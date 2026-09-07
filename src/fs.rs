mod error;

#[cfg(test)]
mod tests;

pub use error::FsError;

use std::fs::File;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Resolves the parent directory of `path`, returning `.` if the parent component is empty.
pub fn parent_directory(path: &Path) -> Result<&Path, FsError> {
    let parent = path.parent().ok_or_else(|| FsError::InsecurePath {
        path: path.to_path_buf(),
        reason: "path has no parent directory",
    })?;
    if parent.as_os_str().is_empty() {
        Ok(Path::new("."))
    } else {
        Ok(parent)
    }
}

/// Checks whether a symlink or object exists at `path` without following symbolic links.
pub fn symlink_exists(path: &Path) -> Result<bool, FsError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(FsError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Opens an existing private file in read-only mode, validating descriptor metadata before return.
///
/// Opening uses nonblocking and no-follow flags to prevent symlink traversal and FIFO hangs.
///
/// # Errors
///
/// Returns `FsError` if opening fails or if the descriptor is not a regular file, has multiple
/// hard links, is not owned by the effective user, or has permissions other than `0600`.
#[cfg(unix)]
pub fn open_private_file(path: &Path) -> Result<File, FsError> {
    use std::os::unix::fs::OpenOptionsExt;

    let flags = open_flags(rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|source| map_open_error(path, source))?;

    let metadata = file.metadata().map_err(|source| FsError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_file_metadata(path, &metadata, rustix::process::geteuid().as_raw())?;
    Ok(file)
}

#[cfg(not(unix))]
pub fn open_private_file(path: &Path) -> Result<File, FsError> {
    let _ = path;
    Err(FsError::Platform(
        "secure private file operations are not supported on this platform",
    ))
}

/// Opens or creates a private lock file in read/write mode without truncation, validating descriptor
/// metadata before return.
///
/// # Errors
///
/// Returns `FsError` if opening fails or if the descriptor is not a regular file, has multiple
/// hard links, is not owned by the effective user, or has permissions other than `0600`.
#[cfg(unix)]
pub fn open_private_lock_file(path: &Path) -> Result<File, FsError> {
    use std::os::unix::fs::OpenOptionsExt;

    let flags = open_flags(rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(flags)
        .open(path)
        .map_err(|source| map_open_error(path, source))?;

    let metadata = file.metadata().map_err(|source| FsError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_file_metadata(path, &metadata, rustix::process::geteuid().as_raw())?;
    Ok(file)
}

#[cfg(not(unix))]
pub fn open_private_lock_file(path: &Path) -> Result<File, FsError> {
    let _ = path;
    Err(FsError::Platform(
        "secure lock file operations are not supported on this platform",
    ))
}

/// Opens an existing private directory, validating descriptor metadata before return.
///
/// # Errors
///
/// Returns `FsError` if opening fails or if the directory descriptor is not a real directory,
/// is not owned by the effective user, or has permissions other than `0700`.
#[cfg(unix)]
pub fn open_private_dir(dir_path: &Path) -> Result<File, FsError> {
    use std::os::unix::fs::OpenOptionsExt;

    let symlink_meta = std::fs::symlink_metadata(dir_path).map_err(|source| FsError::Io {
        path: dir_path.to_path_buf(),
        source,
    })?;
    let effective_uid = rustix::process::geteuid().as_raw();
    validate_dir_metadata(dir_path, &symlink_meta, effective_uid)?;

    let flags = open_flags(
        rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK,
    )?;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(dir_path)
        .map_err(|source| map_open_error(dir_path, source))?;

    let metadata = directory.metadata().map_err(|source| FsError::Io {
        path: dir_path.to_path_buf(),
        source,
    })?;
    validate_dir_metadata(dir_path, &metadata, effective_uid)?;
    Ok(directory)
}

#[cfg(not(unix))]
pub fn open_private_dir(dir_path: &Path) -> Result<File, FsError> {
    let _ = dir_path;
    Err(FsError::Platform(
        "secure private directory operations are not supported on this platform",
    ))
}

/// Validates that an existing directory descriptor is private and owned by the effective user.
pub fn validate_private_dir(dir_path: &Path) -> Result<(), FsError> {
    open_private_dir(dir_path).map(|_| ())
}

/// Safely opens a single-component relative child file from an open directory descriptor.
///
/// # Errors
///
/// Returns `FsError` if `child_name` is not a single relative normal component, if openat fails,
/// or if the opened child does not satisfy private file invariants.
#[cfg(unix)]
pub fn open_private_child(
    dir_path: &Path,
    dir_file: &File,
    child_name: &Path,
) -> Result<File, FsError> {
    let mut components = child_name.components();
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(_)), None) => {}
        _ => {
            return Err(FsError::InsecurePath {
                path: child_name.to_path_buf(),
                reason: "expected a single-component relative file name",
            });
        }
    }

    let full_path = dir_path.join(child_name);
    let descriptor = rustix::fs::openat(
        dir_file,
        child_name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| {
        if source.raw_os_error() == rustix::io::Errno::LOOP.raw_os_error() {
            FsError::InsecurePath {
                path: full_path.clone(),
                reason: "symbolic links are not permitted",
            }
        } else {
            FsError::Io {
                path: full_path.clone(),
                source: source.into(),
            }
        }
    })?;

    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|source| FsError::Io {
        path: full_path.clone(),
        source,
    })?;
    validate_file_metadata(&full_path, &metadata, rustix::process::geteuid().as_raw())?;
    Ok(file)
}

#[cfg(not(unix))]
pub fn open_private_child(
    dir_path: &Path,
    dir_file: &File,
    child_name: &Path,
) -> Result<File, FsError> {
    let _ = (dir_path, dir_file, child_name);
    Err(FsError::Platform(
        "secure directory child operations are not supported on this platform",
    ))
}

/// Creates a directory and any missing parents with mode `0700`.
///
/// # Errors
///
/// Returns `FsError` if directory creation fails.
#[cfg(unix)]
pub fn create_private_dir(dir_path: &Path) -> Result<(), FsError> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.recursive(true);
    match builder.create(dir_path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            if dir_path.is_dir() {
                Ok(())
            } else {
                Err(FsError::Io {
                    path: dir_path.to_path_buf(),
                    source: err,
                })
            }
        }
        Err(source) => Err(FsError::Io {
            path: dir_path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(not(unix))]
pub fn create_private_dir(dir_path: &Path) -> Result<(), FsError> {
    let _ = dir_path;
    Err(FsError::Platform(
        "secure directory creation is not supported on this platform",
    ))
}

/// Repairs permissions of a private file to mode `0600` via descriptor fchmod after validating identity.
///
/// # Errors
///
/// Returns `FsError` if opening fails, identity checks fail, or fchmod fails.
#[cfg(unix)]
pub fn repair_file_permissions(path: &Path) -> Result<(), FsError> {
    use std::os::unix::fs::OpenOptionsExt;

    let flags = open_flags(rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|source| map_open_error(path, source))?;

    repair_file_permissions_descriptor(path, &file, rustix::process::geteuid().as_raw())
}

#[cfg(unix)]
fn repair_file_permissions_descriptor(
    path: &Path,
    file: &File,
    expected_uid: u32,
) -> Result<(), FsError> {
    let metadata = file.metadata().map_err(|source| FsError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_file_identity(path, &metadata, expected_uid)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|source| FsError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata = file.metadata().map_err(|source| FsError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_file_metadata(path, &metadata, expected_uid)
}

#[cfg(not(unix))]
pub fn repair_file_permissions(path: &Path) -> Result<(), FsError> {
    let _ = path;
    Err(FsError::Platform(
        "secure permission repair is not supported on this platform",
    ))
}

/// Repairs permissions of a private directory to mode `0700` via descriptor fchmod after validating identity.
///
/// # Errors
///
/// Returns `FsError` if opening fails, identity checks fail, or fchmod fails.
#[cfg(unix)]
pub fn repair_dir_permissions(path: &Path) -> Result<(), FsError> {
    use std::os::unix::fs::OpenOptionsExt;

    let flags = open_flags(
        rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK,
    )?;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|source| map_open_error(path, source))?;

    repair_dir_permissions_descriptor(path, &directory, rustix::process::geteuid().as_raw())
}

#[cfg(unix)]
fn repair_dir_permissions_descriptor(
    path: &Path,
    directory: &File,
    expected_uid: u32,
) -> Result<(), FsError> {
    let metadata = directory.metadata().map_err(|source| FsError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_dir_identity(path, &metadata, expected_uid)?;
    directory
        .set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(|source| FsError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata = directory.metadata().map_err(|source| FsError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_dir_metadata(path, &metadata, expected_uid)
}

#[cfg(not(unix))]
pub fn repair_dir_permissions(path: &Path) -> Result<(), FsError> {
    let _ = path;
    Err(FsError::Platform(
        "secure permission repair is not supported on this platform",
    ))
}

/// Synchronizes a directory without requiring private mode `0700`.
///
/// Used for directories that may have custom parent permissions (such as custom config parents).
#[cfg(unix)]
pub fn sync_dir(path: &Path) -> Result<(), FsError> {
    use std::os::unix::fs::OpenOptionsExt;

    let flags = open_flags(rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW)?;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|source| map_open_error(path, source))?;
    directory.sync_all().map_err(|source| FsError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
pub fn sync_dir(path: &Path) -> Result<(), FsError> {
    let _ = path;
    Err(FsError::Platform(
        "secure directory sync is not supported on this platform",
    ))
}

/// Synchronizes a managed private directory after validating its mode and ownership.
///
/// Used for cache directories.
#[cfg(unix)]
pub fn sync_private_dir(path: &Path) -> Result<(), FsError> {
    let directory = open_private_dir(path)?;
    directory.sync_all().map_err(|source| FsError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
pub fn sync_private_dir(path: &Path) -> Result<(), FsError> {
    let _ = path;
    Err(FsError::Platform(
        "secure directory sync is not supported on this platform",
    ))
}

/// Creates a private temporary file in `dir` with mode `0600`.
pub fn create_private_tempfile(dir: &Path) -> Result<tempfile::NamedTempFile, FsError> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(".ghst-").suffix(".tmp");
    #[cfg(unix)]
    {
        builder.permissions(std::fs::Permissions::from_mode(0o600));
    }
    builder.tempfile_in(dir).map_err(|source| FsError::Io {
        path: dir.to_path_buf(),
        source,
    })
}

/// Atomically publishes `bytes` to `path` if and only if `path` does not already exist.
///
/// Writes to a temporary file in the destination's parent directory, syncs file and directory.
/// Returns `Ok(true)` if published, or `Ok(false)` if `path` already existed.
///
/// # Durability limitation
/// If directory synchronization fails after the file has been persisted, the file remains at `path`
/// but an error is returned because directory entry durability could not be guaranteed.
#[cfg(unix)]
pub fn publish_if_absent(path: &Path, bytes: &[u8]) -> Result<bool, FsError> {
    publish_if_absent_with_sync(path, bytes, sync_dir)
}

#[cfg(unix)]
fn publish_if_absent_with_sync<F>(
    path: &Path,
    bytes: &[u8],
    sync_dir_fn: F,
) -> Result<bool, FsError>
where
    F: FnOnce(&Path) -> Result<(), FsError>,
{
    use std::io::Write;

    let directory = parent_directory(path)?;
    let mut temporary = create_private_tempfile(directory)?;

    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|source| FsError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    match temporary.persist_noclobber(path) {
        Ok(_) => {
            sync_dir_fn(directory)?;
            Ok(true)
        }
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(FsError::Io {
            path: path.to_path_buf(),
            source: error.error,
        }),
    }
}

#[cfg(not(unix))]
pub fn publish_if_absent(path: &Path, bytes: &[u8]) -> Result<bool, FsError> {
    let _ = (path, bytes);
    Err(FsError::Platform(
        "secure file publication is not supported on this platform",
    ))
}

/// Atomically replaces `path` with `bytes` through a private temporary file in its parent directory.
///
/// Syncs file, replaces atomically, syncs the private parent directory, and validates the published descriptor.
///
/// # Durability limitation
/// If directory synchronization or descriptor validation fails after the replacement file has been
/// persisted, the replaced file remains at `path` but an error is returned because directory entry
/// durability or final descriptor validation could not be completed successfully.
#[cfg(unix)]
pub fn publish_replacement(path: &Path, bytes: &[u8]) -> Result<(), FsError> {
    publish_replacement_with_sync(path, bytes, sync_private_dir)
}

#[cfg(unix)]
fn publish_replacement_with_sync<F>(
    path: &Path,
    bytes: &[u8],
    sync_dir_fn: F,
) -> Result<(), FsError>
where
    F: FnOnce(&Path) -> Result<(), FsError>,
{
    use std::io::Write;

    let directory = parent_directory(path)?;
    let mut temporary = create_private_tempfile(directory)?;

    temporary
        .as_file_mut()
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|source| FsError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    temporary.persist(path).map_err(|error| FsError::Io {
        path: path.to_path_buf(),
        source: error.error,
    })?;

    sync_dir_fn(directory)?;

    // Validate the published descriptor before returning success
    let file = open_private_file(path)?;
    drop(file);
    Ok(())
}

#[cfg(not(unix))]
pub fn publish_replacement(path: &Path, bytes: &[u8]) -> Result<(), FsError> {
    let _ = (path, bytes);
    Err(FsError::Platform(
        "secure file publication is not supported on this platform",
    ))
}

#[cfg(unix)]
fn map_open_error(path: &Path, source: std::io::Error) -> FsError {
    if source.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
        FsError::InsecurePath {
            path: path.to_path_buf(),
            reason: "symbolic links are not permitted",
        }
    } else {
        FsError::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

#[cfg(unix)]
fn open_flags(flags: rustix::fs::OFlags) -> Result<i32, FsError> {
    i32::try_from(flags.bits())
        .map_err(|_| FsError::Platform("required filesystem open flags are not supported"))
}

#[cfg(unix)]
fn validate_file_identity(
    path: &Path,
    metadata: &std::fs::Metadata,
    expected_uid: u32,
) -> Result<(), FsError> {
    if metadata.file_type().is_symlink() {
        return Err(FsError::InsecurePath {
            path: path.to_path_buf(),
            reason: "symbolic links are not permitted",
        });
    }
    if !metadata.is_file() {
        return Err(FsError::InsecurePath {
            path: path.to_path_buf(),
            reason: "expected a regular file",
        });
    }
    if metadata.nlink() != 1 {
        return Err(FsError::InsecurePath {
            path: path.to_path_buf(),
            reason: "hard links are not permitted",
        });
    }
    if metadata.uid() != expected_uid {
        return Err(FsError::InsecurePath {
            path: path.to_path_buf(),
            reason: "not owned by the effective user",
        });
    }
    Ok(())
}

#[cfg(unix)]
fn validate_file_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
    expected_uid: u32,
) -> Result<(), FsError> {
    validate_file_identity(path, metadata, expected_uid)?;
    if metadata.permissions().mode() & 0o7777 != 0o600 {
        return Err(FsError::InsecurePath {
            path: path.to_path_buf(),
            reason: "unexpected permissions",
        });
    }
    Ok(())
}

#[cfg(unix)]
fn validate_dir_identity(
    path: &Path,
    metadata: &std::fs::Metadata,
    expected_uid: u32,
) -> Result<(), FsError> {
    if metadata.file_type().is_symlink() {
        return Err(FsError::InsecurePath {
            path: path.to_path_buf(),
            reason: "symbolic links are not permitted",
        });
    }
    if !metadata.is_dir() {
        return Err(FsError::InsecurePath {
            path: path.to_path_buf(),
            reason: "expected a directory",
        });
    }
    if metadata.uid() != expected_uid {
        return Err(FsError::InsecurePath {
            path: path.to_path_buf(),
            reason: "not owned by the effective user",
        });
    }
    Ok(())
}

#[cfg(unix)]
fn validate_dir_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
    expected_uid: u32,
) -> Result<(), FsError> {
    validate_dir_identity(path, metadata, expected_uid)?;
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err(FsError::InsecurePath {
            path: path.to_path_buf(),
            reason: "unexpected permissions",
        });
    }
    Ok(())
}
