use super::*;
use std::fs;
use std::io::Read;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

#[test]
fn parent_directory_handles_relative_and_missing_parents() {
    assert_eq!(
        parent_directory(Path::new("file.txt")).unwrap(),
        Path::new(".")
    );
    assert_eq!(
        parent_directory(Path::new("dir/file.txt")).unwrap(),
        Path::new("dir")
    );
    assert!(parent_directory(Path::new("")).is_err());
}

#[test]
fn symlink_exists_distinguishes_absence_and_presence() {
    let temp = tempfile::tempdir().unwrap();
    let present = temp.path().join("present");
    fs::write(&present, b"content").unwrap();
    let absent = temp.path().join("absent");

    assert!(symlink_exists(&present).unwrap());
    assert!(!symlink_exists(&absent).unwrap());

    #[cfg(unix)]
    {
        let link = temp.path().join("dangling-link");
        symlink(&absent, &link).unwrap();
        // Dangling symlink itself exists even if target is absent
        assert!(symlink_exists(&link).unwrap());
    }
}

#[cfg(unix)]
#[test]
fn open_private_file_validates_descriptor_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let valid = temp.path().join("valid.txt");
    fs::write(&valid, b"secret").unwrap();
    fs::set_permissions(&valid, fs::Permissions::from_mode(0o600)).unwrap();

    let mut file = open_private_file(&valid).unwrap();
    let mut buf = String::new();
    file.read_to_string(&mut buf).unwrap();
    assert_eq!(buf, "secret");

    // Insecure permissions
    fs::set_permissions(&valid, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        open_private_file(&valid),
        Err(FsError::InsecurePath {
            reason: "unexpected permissions",
            ..
        })
    ));
    fs::set_permissions(&valid, fs::Permissions::from_mode(0o600)).unwrap();

    // Hard link rejection
    let hard_link = temp.path().join("hardlink.txt");
    fs::hard_link(&valid, &hard_link).unwrap();
    assert!(matches!(
        open_private_file(&valid),
        Err(FsError::InsecurePath {
            reason: "hard links are not permitted",
            ..
        })
    ));

    // Symlink rejection
    let link = temp.path().join("link.txt");
    symlink(&valid, &link).unwrap();
    assert!(matches!(
        open_private_file(&link),
        Err(FsError::InsecurePath {
            reason: "symbolic links are not permitted",
            ..
        })
    ));

    // Wrong object type (directory where file expected)
    let dir = temp.path().join("subdir");
    fs::create_dir(&dir).unwrap();
    assert!(matches!(
        open_private_file(&dir),
        Err(FsError::InsecurePath {
            reason: "expected a regular file",
            ..
        })
    ));
}

#[cfg(unix)]
#[test]
fn open_private_lock_file_validates_descriptor_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let lock_path = temp.path().join(".test.lock");

    // Creation when absent
    let file = open_private_lock_file(&lock_path).unwrap();
    drop(file);
    assert_eq!(
        fs::metadata(&lock_path).unwrap().permissions().mode() & 0o7777,
        0o600
    );

    // Existing insecure permissions
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        open_private_lock_file(&lock_path),
        Err(FsError::InsecurePath {
            reason: "unexpected permissions",
            ..
        })
    ));
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();

    // Symlinked lock file
    let link = temp.path().join("link.lock");
    symlink(&lock_path, &link).unwrap();
    assert!(matches!(
        open_private_lock_file(&link),
        Err(FsError::InsecurePath {
            reason: "symbolic links are not permitted",
            ..
        })
    ));

    // Hard-linked lock file
    let target = temp.path().join("target.lock");
    fs::write(&target, b"").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    let linked = temp.path().join("linked.lock");
    fs::hard_link(&target, &linked).unwrap();
    assert!(matches!(
        open_private_lock_file(&linked),
        Err(FsError::InsecurePath {
            reason: "hard links are not permitted",
            ..
        })
    ));
}

#[cfg(unix)]
#[test]
fn open_private_dir_validates_descriptor_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let valid_dir = temp.path().join("valid_dir");
    create_private_dir(&valid_dir).unwrap();
    assert!(open_private_dir(&valid_dir).is_ok());

    // Insecure permissions
    fs::set_permissions(&valid_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        open_private_dir(&valid_dir),
        Err(FsError::InsecurePath {
            reason: "unexpected permissions",
            ..
        })
    ));
    fs::set_permissions(&valid_dir, fs::Permissions::from_mode(0o700)).unwrap();

    // Symlink directory rejection
    let link_dir = temp.path().join("link_dir");
    symlink(&valid_dir, &link_dir).unwrap();
    assert!(matches!(
        open_private_dir(&link_dir),
        Err(FsError::InsecurePath {
            reason: "symbolic links are not permitted",
            ..
        })
    ));

    // Regular file where directory expected
    let reg_file = temp.path().join("file.txt");
    fs::write(&reg_file, b"").unwrap();
    assert!(matches!(
        open_private_dir(&reg_file),
        Err(FsError::InsecurePath {
            reason: "expected a directory",
            ..
        })
    ));
}

#[cfg(unix)]
#[test]
fn open_private_child_rejects_invalid_components_and_uses_relative_descriptor() {
    let temp = tempfile::tempdir().unwrap();
    let dir_path = temp.path().join("dir");
    create_private_dir(&dir_path).unwrap();
    let child_name = Path::new("child.txt");
    let child_path = dir_path.join(child_name);
    fs::write(&child_path, b"child-secret").unwrap();
    fs::set_permissions(&child_path, fs::Permissions::from_mode(0o600)).unwrap();

    let dir = open_private_dir(&dir_path).unwrap();
    let mut child = open_private_child(&dir_path, &dir, child_name).unwrap();
    let mut buf = String::new();
    child.read_to_string(&mut buf).unwrap();
    assert_eq!(buf, "child-secret");

    let symlink_name = Path::new("child-link.txt");
    symlink(&child_path, dir_path.join(symlink_name)).unwrap();
    assert!(matches!(
        open_private_child(&dir_path, &dir, symlink_name),
        Err(FsError::InsecurePath {
            reason: "symbolic links are not permitted",
            ..
        })
    ));

    // Reject absolute path
    assert!(matches!(
        open_private_child(&dir_path, &dir, Path::new("/etc/passwd")),
        Err(FsError::InsecurePath {
            reason: "expected a single-component relative file name",
            ..
        })
    ));

    // Reject parent traversal
    assert!(matches!(
        open_private_child(&dir_path, &dir, Path::new("../foo")),
        Err(FsError::InsecurePath {
            reason: "expected a single-component relative file name",
            ..
        })
    ));

    // Reject multi-component path
    assert!(matches!(
        open_private_child(&dir_path, &dir, Path::new("sub/file.txt")),
        Err(FsError::InsecurePath {
            reason: "expected a single-component relative file name",
            ..
        })
    ));
}

#[cfg(unix)]
#[test]
fn permission_repair_validates_descriptor_before_mutation_and_leaves_target_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let file_path = temp.path().join("file.txt");
    fs::write(&file_path, b"content").unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644)).unwrap();

    let file = File::open(&file_path).unwrap();
    let wrong_uid = file.metadata().unwrap().uid().wrapping_add(1);
    assert!(matches!(
        repair_file_permissions_descriptor(&file_path, &file, wrong_uid),
        Err(FsError::InsecurePath {
            reason: "not owned by the effective user",
            ..
        })
    ));
    // Verify target permissions were left unchanged
    assert_eq!(
        file.metadata().unwrap().permissions().mode() & 0o7777,
        0o644
    );

    // Directory repair with wrong UID
    let dir_path = temp.path().join("dir");
    fs::create_dir(&dir_path).unwrap();
    fs::set_permissions(&dir_path, fs::Permissions::from_mode(0o755)).unwrap();
    let dir = File::open(&dir_path).unwrap();
    let wrong_uid = dir.metadata().unwrap().uid().wrapping_add(1);
    assert!(matches!(
        repair_dir_permissions_descriptor(&dir_path, &dir, wrong_uid),
        Err(FsError::InsecurePath {
            reason: "not owned by the effective user",
            ..
        })
    ));
    assert_eq!(dir.metadata().unwrap().permissions().mode() & 0o7777, 0o755);

    // Normal successful repair
    repair_file_permissions(&file_path).unwrap();
    assert_eq!(
        fs::metadata(&file_path).unwrap().permissions().mode() & 0o7777,
        0o600
    );

    repair_dir_permissions(&dir_path).unwrap();
    assert_eq!(
        fs::metadata(&dir_path).unwrap().permissions().mode() & 0o7777,
        0o700
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn nonblocking_opening_rejects_fifos_without_blocking() {
    const SUBPROCESS_ENV: &str = "GHST_TEST_FIFO_SUBPROCESS_WORKER";

    if std::env::var_os(SUBPROCESS_ENV).is_some() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fifo = temp.path().join("test.fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RWXU,
            0,
        )
        .expect("mknodat");

        // open_private_file rejects without hanging
        assert!(matches!(
            open_private_file(&fifo),
            Err(FsError::InsecurePath {
                reason: "expected a regular file",
                ..
            })
        ));

        // open_private_lock_file rejects without hanging
        assert!(matches!(
            open_private_lock_file(&fifo),
            Err(FsError::InsecurePath {
                reason: "expected a regular file",
                ..
            })
        ));

        // repair_file_permissions rejects without hanging
        assert!(matches!(
            repair_file_permissions(&fifo),
            Err(FsError::InsecurePath {
                reason: "expected a regular file",
                ..
            })
        ));
        return;
    }

    let test_exe = std::env::current_exe().expect("current_exe");
    let mut child = std::process::Command::new(test_exe)
        .arg("--exact")
        .arg("fs::tests::nonblocking_opening_rejects_fifos_without_blocking")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(SUBPROCESS_ENV, "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn FIFO check child process");

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().expect("failed to poll child process") {
            break status;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            panic!("FIFO checks hung and timed out after {timeout:?}");
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = std::io::Read::read_to_end(&mut out, &mut stdout);
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = std::io::Read::read_to_end(&mut err, &mut stderr);
    }

    assert!(
        status.success(),
        "FIFO subprocess failed with status {status:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
}

#[test]
fn publish_if_absent_is_private_atomic_and_preserves_existing() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("new_file.txt");

    // When absent: writes bytes, mode 0600, returns true
    assert!(publish_if_absent(&path, b"initial content").unwrap());
    assert_eq!(fs::read(&path).unwrap(), b"initial content");

    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o600
    );

    // When already exists: returns false, preserves existing content
    assert!(!publish_if_absent(&path, b"different content").unwrap());
    assert_eq!(fs::read(&path).unwrap(), b"initial content");
}

#[test]
fn publish_replacement_is_atomic_and_private() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("cache");
    create_private_dir(&dir).unwrap();
    let path = dir.join("file.txt");

    publish_replacement(&path, b"first generation").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"first generation");

    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o600
    );

    publish_replacement(&path, b"second generation").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"second generation");
}

#[test]
fn publish_replacement_preserves_destination_on_pre_publication_failure() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("cache");
    create_private_dir(&dir).unwrap();
    let target = dir.join("file.txt");

    // Write original file
    publish_replacement(&target, b"initial content").unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"initial content");

    #[cfg(unix)]
    {
        // Make directory read-only so temporary file creation fails before publication
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        let result = publish_replacement(&target, b"attempted new content");
        assert!(result.is_err());

        // Restore permissions to inspect directory
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();

        // Destination file is untouched and preserved
        assert_eq!(fs::read(&target).unwrap(), b"initial content");

        // No temporary files left behind
        let remaining_files: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(remaining_files, vec!["file.txt"]);
    }
}

#[test]
fn publish_if_absent_preserves_destination_on_pre_publication_failure() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("config");
    create_private_dir(&dir).unwrap();
    let target = dir.join("config.toml");

    publish_if_absent(&target, b"original config").unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"original config");

    #[cfg(unix)]
    {
        // Make directory read-only so temporary file creation fails before publication
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        let result = publish_if_absent(&target, b"new config");
        assert!(result.is_err());

        // Restore permissions to inspect directory
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();

        // Destination file is untouched and preserved
        assert_eq!(fs::read(&target).unwrap(), b"original config");

        // No temporary files left behind
        let remaining_files: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(remaining_files, vec!["config.toml"]);
    }
}

#[cfg(unix)]
#[test]
fn publication_propagates_post_publication_directory_sync_failure() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("cache");
    create_private_dir(&dir).unwrap();
    let target = dir.join("target.txt");

    // Pre-create target
    publish_replacement(&target, b"first generation").unwrap();

    // Directory sync failure after publication in publish_replacement
    let sync_err = || {
        Err(FsError::Io {
            path: dir.clone(),
            source: std::io::Error::other("simulated sync failure"),
        })
    };

    let result = publish_replacement_with_sync(&target, b"second generation", |_| sync_err());
    assert!(matches!(
        result,
        Err(FsError::Io { source, .. }) if source.to_string() == "simulated sync failure"
    ));
    // Note durability limitation: the file content was persisted before the sync failure
    assert_eq!(fs::read(&target).unwrap(), b"second generation");

    // Directory sync failure after publication in publish_if_absent
    let target_absent = dir.join("new_file.txt");
    let result = publish_if_absent_with_sync(&target_absent, b"absent content", |_| sync_err());
    assert!(matches!(
        result,
        Err(FsError::Io { source, .. }) if source.to_string() == "simulated sync failure"
    ));
    // The file content was persisted before the sync failure
    assert_eq!(fs::read(&target_absent).unwrap(), b"absent content");
}

#[cfg(unix)]
#[test]
fn sync_dir_and_sync_private_dir_propagate_io_errors() {
    let temp = tempfile::tempdir().unwrap();
    let nonexistent = temp.path().join("nonexistent");

    // Both functions propagate error on nonexistent directory
    assert!(matches!(sync_dir(&nonexistent), Err(FsError::Io { .. })));
    assert!(matches!(
        sync_private_dir(&nonexistent),
        Err(FsError::Io { .. })
    ));

    // sync_dir on a regular file rejects because DIRECTORY flag fails open
    let file_path = temp.path().join("regular_file");
    fs::write(&file_path, b"data").unwrap();
    assert!(matches!(sync_dir(&file_path), Err(FsError::Io { .. })));

    // sync_private_dir on directory with insecure permissions rejects
    let insecure_dir = temp.path().join("insecure_dir");
    create_private_dir(&insecure_dir).unwrap();
    fs::set_permissions(&insecure_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        sync_private_dir(&insecure_dir),
        Err(FsError::InsecurePath {
            reason: "unexpected permissions",
            ..
        })
    ));
}

#[cfg(unix)]
#[test]
fn create_private_dir_creates_privately_and_leaves_existing_policy_to_callers() {
    let temp = tempfile::tempdir().unwrap();

    // Creates new private directory with mode 0700
    let new_dir = temp.path().join("new_dir");
    create_private_dir(&new_dir).unwrap();
    assert_eq!(
        fs::metadata(&new_dir).unwrap().permissions().mode() & 0o7777,
        0o700
    );

    // Existing private directory is accepted idempotently
    assert!(create_private_dir(&new_dir).is_ok());

    // Symlink pointing to directory is rejected
    let link_dir = temp.path().join("link_dir");
    symlink(&new_dir, &link_dir).unwrap();
    assert!(matches!(
        create_private_dir(&link_dir),
        Err(FsError::InsecurePath {
            reason: "symbolic links are not permitted",
            ..
        })
    ));

    // Existing directory permissions are left for the caller to validate or repair
    let insecure_dir = temp.path().join("insecure_dir");
    create_private_dir(&insecure_dir).unwrap();
    fs::set_permissions(&insecure_dir, fs::Permissions::from_mode(0o755)).unwrap();
    create_private_dir(&insecure_dir).unwrap();
    assert_eq!(
        fs::metadata(&insecure_dir).unwrap().permissions().mode() & 0o7777,
        0o755
    );
    assert!(matches!(
        validate_private_dir(&insecure_dir),
        Err(FsError::InsecurePath {
            reason: "unexpected permissions",
            ..
        })
    ));

    // Existing regular file fails with I/O error
    let file_path = temp.path().join("file.txt");
    fs::write(&file_path, b"").unwrap();
    assert!(matches!(
        create_private_dir(&file_path),
        Err(FsError::Io { .. })
    ));
}
