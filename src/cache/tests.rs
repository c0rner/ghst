use crate::cache::error::CacheError;
use crate::cache::fs::{cache_file_path, create_private_tempfile, ensure_cache_dir};
use crate::cache::key::compute_cache_key;
use crate::cache::storage::{
    delete_cache_entry, list_cache_entries, load_cache_entry, save_cache_entry,
};
use crate::cache::types::{
    CACHE_SCHEMA_VERSION, CacheEntry, DerivedCacheEntry, RootCacheEntry, SaveCacheEntry,
    TokenExpiry, authority_fingerprint, format_rfc3339,
};
use std::fs;
use std::io::Write;
use std::sync::{Arc, Barrier};
use std::thread;
use time::{Duration, OffsetDateTime};

fn root_key() -> String {
    compute_cache_key("developer", "all")
}

fn root_entry(token: &str, expiry: OffsetDateTime, authority: &str) -> CacheEntry {
    CacheEntry::Root(RootCacheEntry {
        version: CACHE_SCHEMA_VERSION,
        profile: "developer".into(),
        authority_fingerprint: authority.into(),
        github_user: "octocat".into(),
        issued_at: format_rfc3339(OffsetDateTime::now_utc()),
        expires_at: TokenExpiry::new(expiry),
        access_token: token.into(),
    })
}

fn cache_dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn cache_key_is_profile_and_canonical_scope_hash() {
    let first = compute_cache_key("developer", "all");
    let second = compute_cache_key("reader", "c0rner/ghst");
    assert_ne!(first, second);
    assert_eq!(
        first,
        "44e9b443f6a49a44a6a5588f3be3923a3c1ec1c1f2bfd419addebcde4d598411"
    );
}

#[test]
fn secrets_are_redacted_and_zeroizing_type_serializes() {
    let entry = root_entry(
        "ghu_secret_123456",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    let debug = format!("{entry:?}");
    assert!(!debug.contains("ghu_secret_123456"));
    assert!(debug.contains("[REDACTED]"));
    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains("ghu_secret_123456"));
    let restored: CacheEntry = serde_json::from_str(&json).unwrap();
    assert!(restored.is_current());
}

#[test]
fn save_creates_private_directory_and_entry() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let entry = root_entry(
        "first",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    assert!(matches!(
        save_cache_entry(&directory, &root_key(), &entry).unwrap(),
        SaveCacheEntry::Saved
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        assert_eq!(
            fs::metadata(cache_file_path(&directory, &root_key()))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        assert_eq!(
            fs::metadata(directory.join(".cache.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }
}

#[cfg(unix)]
#[test]
fn insecure_or_symlinked_cache_state_fails_closed() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let temp = cache_dir();
    let insecure = temp.path().join("insecure");
    fs::create_dir(&insecure).unwrap();
    fs::set_permissions(&insecure, fs::Permissions::from_mode(0o755)).unwrap();
    let entry = root_entry(
        "token",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    assert!(matches!(
        save_cache_entry(&insecure, &root_key(), &entry),
        Err(CacheError::InsecurePath { .. })
    ));

    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    let link = temp.path().join("link");
    symlink(target, &link).unwrap();
    assert!(matches!(
        ensure_cache_dir(&link),
        Err(CacheError::InsecurePath { .. })
    ));
}

#[cfg(unix)]
#[test]
fn insecure_global_lock_file_fails_closed() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let entry = root_entry(
        "token",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );

    let symlink_temp = cache_dir();
    let symlink_cache = symlink_temp.path().join("cache");
    ensure_cache_dir(&symlink_cache).unwrap();
    let symlink_target = symlink_temp.path().join("target");
    fs::write(&symlink_target, b"").unwrap();
    symlink(&symlink_target, symlink_cache.join(".cache.lock")).unwrap();
    assert!(matches!(
        save_cache_entry(&symlink_cache, &root_key(), &entry),
        Err(CacheError::InsecurePath { .. })
    ));

    let mode_temp = cache_dir();
    let mode_cache = mode_temp.path().join("cache");
    ensure_cache_dir(&mode_cache).unwrap();
    let mode_lock = mode_cache.join(".cache.lock");
    fs::write(&mode_lock, b"").unwrap();
    fs::set_permissions(&mode_lock, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        save_cache_entry(&mode_cache, &root_key(), &entry),
        Err(CacheError::InsecurePath { .. })
    ));

    let hard_link_temp = cache_dir();
    let hard_link_cache = hard_link_temp.path().join("cache");
    ensure_cache_dir(&hard_link_cache).unwrap();
    let hard_link_target = hard_link_temp.path().join("target");
    fs::write(&hard_link_target, b"").unwrap();
    fs::set_permissions(&hard_link_target, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&hard_link_target, hard_link_cache.join(".cache.lock")).unwrap();
    assert!(matches!(
        save_cache_entry(&hard_link_cache, &root_key(), &entry),
        Err(CacheError::InsecurePath { .. })
    ));
}

#[test]
fn malformed_entry_is_never_overwritten() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    ensure_cache_dir(&directory).unwrap();
    let path = cache_file_path(&directory, &root_key());
    let mut file = create_private_tempfile(&directory).unwrap();
    file.write_all(b"{ malformed").unwrap();
    file.persist(&path).unwrap();
    let replacement = root_entry(
        "replacement",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    assert!(matches!(
        save_cache_entry(&directory, &root_key(), &replacement),
        Err(CacheError::Json(_))
    ));
    assert_eq!(fs::read_to_string(path).unwrap(), "{ malformed");
}

#[test]
fn malformed_current_expiry_is_not_downgraded_to_legacy_or_overwritten() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    ensure_cache_dir(&directory).unwrap();
    let path = cache_file_path(&directory, &root_key());
    let invalid = r#"{
        "kind":"root",
        "version":2,
        "profile":"developer",
        "authority_fingerprint":"authority",
        "github_user":"octocat",
        "issued_at":"2026-01-01T00:00:00Z",
        "expires_at":"invalid",
        "access_token":"existing"
    }"#;
    let mut file = create_private_tempfile(&directory).unwrap();
    file.write_all(invalid.as_bytes()).unwrap();
    file.persist(&path).unwrap();
    assert!(matches!(
        load_cache_entry(&directory, &root_key()),
        Err(CacheError::Json(_))
    ));
    let replacement = root_entry(
        "replacement",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    assert!(matches!(
        save_cache_entry(&directory, &root_key(), &replacement),
        Err(CacheError::Json(_))
    ));
    assert_eq!(fs::read_to_string(path).unwrap(), invalid);
}

#[test]
fn legacy_and_stale_provenance_are_replaced_only_after_candidate_exists() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    ensure_cache_dir(&directory).unwrap();
    let path = cache_file_path(&directory, &root_key());
    let legacy = r#"{
            "kind":"root",
            "profile":"developer",
            "github_user":"octocat",
            "issued_at":"2026-01-01T00:00:00Z",
            "expires_at":"not-even-a-timestamp",
            "access_token":"legacy-token"
        }"#;
    let mut file = create_private_tempfile(&directory).unwrap();
    file.write_all(legacy.as_bytes()).unwrap();
    file.persist(&path).unwrap();
    assert!(matches!(
        load_cache_entry(&directory, &root_key()),
        Err(CacheError::Json(_))
    ));

    let current = root_entry(
        "current",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "new-authority",
    );
    assert!(matches!(
        save_cache_entry(&directory, &root_key(), &current),
        Err(CacheError::Json(_))
    ));
    fs::remove_file(&path).unwrap();
    assert!(matches!(
        save_cache_entry(&directory, &root_key(), &current).unwrap(),
        SaveCacheEntry::Saved
    ));

    let changed = root_entry(
        "changed",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "changed-authority",
    );
    assert!(matches!(
        save_cache_entry(&directory, &root_key(), &changed).unwrap(),
        SaveCacheEntry::Saved
    ));
}

#[test]
fn compatible_entry_is_retained_and_wrong_kind_fails_closed() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let existing = root_entry(
        "existing",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "same",
    );
    let candidate = root_entry(
        "candidate",
        OffsetDateTime::now_utc() + Duration::hours(2),
        "same",
    );
    save_cache_entry(&directory, &root_key(), &existing).unwrap();
    let retained = save_cache_entry(&directory, &root_key(), &candidate).unwrap();
    match retained {
        SaveCacheEntry::Retained(entry) => match *entry {
            CacheEntry::Root(RootCacheEntry { access_token, .. }) => {
                assert_eq!(access_token.as_ref(), "existing");
            }
            CacheEntry::Derived(_) => panic!("expected retained root entry"),
        },
        SaveCacheEntry::Saved => panic!("expected compatible entry to be retained"),
    }

    let other = temp.path().join("other");
    let derived = CacheEntry::Derived(DerivedCacheEntry {
        version: CACHE_SCHEMA_VERSION,
        profile: "developer".into(),
        source_profile: "developer".into(),
        parent_generation: "parent".into(),
        policy_fingerprint: "policy".into(),
        github_user: "octocat".into(),
        repo_scope: "all".into(),
        issued_at: format_rfc3339(OffsetDateTime::now_utc()),
        expires_at: TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(1)),
        access_token: "derived".into(),
    });
    save_cache_entry(&other, &root_key(), &derived).unwrap();
    assert!(matches!(
        save_cache_entry(&other, &root_key(), &candidate),
        Err(CacheError::UnexpectedKind { .. })
    ));
}

#[test]
fn inconsistent_embedded_key_metadata_fails_closed() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let wrong_key = compute_cache_key("different", "all");
    let entry = root_entry(
        "token",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    assert!(matches!(
        save_cache_entry(&directory, &wrong_key, &entry),
        Err(CacheError::InconsistentMetadata { .. })
    ));
}

#[test]
fn concurrent_saves_retain_one_compatible_winner() {
    let temp = cache_dir();
    let directory = Arc::new(temp.path().join("cache"));
    let barrier = Arc::new(Barrier::new(2));
    let first = root_entry(
        "first",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    let second = root_entry(
        "second",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    let handles = [first, second].map(|entry| {
        let directory = Arc::clone(&directory);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            save_cache_entry(&directory, &root_key(), &entry).unwrap()
        })
    });
    let results = handles.map(|handle| handle.join().unwrap());
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
}

#[test]
fn delete_and_list_operate_on_validated_entries() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let entry = root_entry(
        "token",
        OffsetDateTime::now_utc() + Duration::hours(1),
        &authority_fingerprint("id", "account"),
    );
    save_cache_entry(&directory, &root_key(), &entry).unwrap();
    fs::write(directory.join(format!("{}.lock", root_key())), b"legacy").unwrap();
    assert_eq!(list_cache_entries(&directory).unwrap().len(), 1);
    assert!(delete_cache_entry(&directory, &root_key()).unwrap());
    assert!(list_cache_entries(&directory).unwrap().is_empty());
}
