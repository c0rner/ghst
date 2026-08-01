#[cfg(test)]
mod tests {
    use crate::cache::error::CacheError;
    use crate::cache::fs::{cache_file_path, create_private_tempfile, ensure_cache_dir};
    use crate::cache::key::compute_cache_key;
    use crate::cache::storage::{
        delete_cache_entry, list_cache_entries, load_cache_entry, save_cache_entry,
    };
    use crate::cache::types::{
        CacheEntry, RootCacheEntry, SaveCacheEntry, format_rfc3339, is_timestamp_valid,
    };
    use std::fs;
    use std::io::Write;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use time::{Duration, OffsetDateTime};

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
