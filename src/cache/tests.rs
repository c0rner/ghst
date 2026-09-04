use crate::cache::cache_epoch;
use crate::cache::error::CacheError;
use crate::cache::fs::{cache_file_path, create_private_tempfile, ensure_cache_dir};
use crate::cache::key::{compute_cache_key, compute_run_cache_key};
use crate::cache::run_storage;
use crate::cache::storage::{
    DeleteBaseOutcome, claim_abandoned_run, delete_base_if_generation, delete_cache_entry,
    delete_run_after_cleanup, load_cache_entry, replace_cache_candidate, save_cache_entry,
};
use crate::cache::types::{
    BaseCacheEntry, CACHE_SCHEMA_VERSION, CacheEntry, RUN_CACHE_SCHEMA_VERSION, ReplaceCacheEntry,
    RunCacheEntry, RunState, SaveCacheEntry, ScopedCacheEntry, authority_fingerprint,
};
use crate::domain::credential::TokenExpiry;
use std::fs;
use std::io::Write;
use std::sync::{Arc, Barrier};
use std::thread;
use time::{Duration, OffsetDateTime};

fn base_key() -> String {
    compute_cache_key("developer", "all")
}

fn base_entry(token: &str, expiry: OffsetDateTime, authority: &str) -> CacheEntry {
    CacheEntry::Base(BaseCacheEntry {
        version: CACHE_SCHEMA_VERSION,
        profile: "developer".into(),
        authority_fingerprint: authority.into(),
        github_user: "octocat".into(),
        expires_at: TokenExpiry::new(expiry),
        access_token: token.into(),
    })
}

fn cache_dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn run_entry(run_id: &str, state: RunState) -> CacheEntry {
    CacheEntry::Run(RunCacheEntry {
        version: RUN_CACHE_SCHEMA_VERSION,
        run_id: run_id.into(),
        state,
        wrapper_pid: 100,
        child_pid: None,
        command: "true".into(),
        profile: "reader".into(),
        source_profile: "developer".into(),
        source_authority_fingerprint: authority_fingerprint("id", "acme"),
        github_user: "octocat".into(),
        repo_scope: "acme/api".into(),
        expires_at: TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(1)),
        access_token: "run-token".into(),
    })
}

fn scoped_entry(token: &str, expiry: OffsetDateTime, parent_generation: &str) -> CacheEntry {
    CacheEntry::Scoped(ScopedCacheEntry {
        version: CACHE_SCHEMA_VERSION,
        profile: "reader".into(),
        source_profile: "developer".into(),
        source_authority_fingerprint: "authority".into(),
        parent_generation: parent_generation.into(),
        policy_fingerprint: "policy".into(),
        github_user: "octocat".into(),
        repo_scope: "acme/api".into(),
        expires_at: TokenExpiry::new(expiry),
        access_token: token.into(),
    })
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
fn base_generation_deletion_is_atomic_compare_and_delete() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let now = OffsetDateTime::now_utc();
    let rejected = base_entry("rejected", now + Duration::hours(1), "authority");
    let CacheEntry::Base(rejected_data) = &rejected else {
        panic!("expected base")
    };
    let rejected_generation = rejected_data.generation_fingerprint();
    save_cache_entry(&directory, &base_key(), &rejected).unwrap();

    assert_eq!(
        delete_base_if_generation(&directory, &base_key(), &rejected_generation).unwrap(),
        DeleteBaseOutcome::Deleted
    );
    assert!(load_cache_entry(&directory, &base_key()).unwrap().is_none());
    assert_eq!(
        delete_base_if_generation(&directory, &base_key(), &rejected_generation).unwrap(),
        DeleteBaseOutcome::Missing
    );

    let replacement = base_entry("replacement", now + Duration::hours(1), "authority");
    save_cache_entry(&directory, &base_key(), &replacement).unwrap();
    assert_eq!(
        delete_base_if_generation(&directory, &base_key(), &rejected_generation).unwrap(),
        DeleteBaseOutcome::Changed
    );
    assert_eq!(
        load_cache_entry(&directory, &base_key())
            .unwrap()
            .unwrap()
            .access_token()
            .as_ref(),
        "replacement"
    );
}

#[test]
fn renewal_compare_and_replace_returns_the_exact_displaced_entry() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let now = OffsetDateTime::now_utc();
    let base = base_entry("base", now + Duration::hours(1), "authority");
    let CacheEntry::Base(base_data) = &base else {
        panic!("expected base")
    };
    let generation = base_data.generation_fingerprint();
    save_cache_entry(&directory, &base_key(), &base).unwrap();
    let key = compute_cache_key("reader", "acme/api");
    let selected = scoped_entry("selected", now + Duration::minutes(5), &generation);
    let candidate = scoped_entry("candidate", now + Duration::hours(1), &generation);
    save_cache_entry(&directory, &key, &selected).unwrap();
    let epoch = cache_epoch(&directory).unwrap();

    let result = replace_cache_candidate(
        &directory,
        &key,
        &selected,
        &candidate,
        epoch,
        (&base_key(), &generation),
        now,
    )
    .unwrap();

    let ReplaceCacheEntry::Replaced(displaced) = result else {
        panic!("expected replacement")
    };
    assert_eq!(displaced.access_token().as_ref(), "selected");
    assert_eq!(
        load_cache_entry(&directory, &key)
            .unwrap()
            .unwrap()
            .access_token()
            .as_ref(),
        "candidate"
    );
}

#[test]
fn renewal_compare_and_replace_retains_a_compatible_concurrent_winner() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let now = OffsetDateTime::now_utc();
    let base = base_entry("base", now + Duration::hours(1), "authority");
    let CacheEntry::Base(base_data) = &base else {
        panic!("expected base")
    };
    let generation = base_data.generation_fingerprint();
    save_cache_entry(&directory, &base_key(), &base).unwrap();
    let key = compute_cache_key("reader", "acme/api");
    let selected = scoped_entry("selected", now + Duration::minutes(5), &generation);
    save_cache_entry(&directory, &key, &selected).unwrap();
    let epoch = cache_epoch(&directory).unwrap();
    delete_cache_entry(&directory, &key).unwrap();
    let winner = scoped_entry("winner", now + Duration::hours(1), &generation);
    save_cache_entry(&directory, &key, &winner).unwrap();
    let candidate = scoped_entry("candidate", now + Duration::hours(1), &generation);

    let result = replace_cache_candidate(
        &directory,
        &key,
        &selected,
        &candidate,
        epoch,
        (&base_key(), &generation),
        now,
    )
    .unwrap();

    let ReplaceCacheEntry::Retained(retained) = result else {
        panic!("expected retained winner")
    };
    assert_eq!(retained.access_token().as_ref(), "winner");
}

#[test]
fn run_keys_are_unique_domain_separated_and_reject_collisions() {
    let first = compute_run_cache_key("first");
    let second = compute_run_cache_key("second");
    assert_ne!(first, second);
    assert_ne!(first, compute_cache_key("run", "first"));

    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let entry = run_entry("first", RunState::Pending);
    assert!(matches!(
        save_cache_entry(&directory, &first, &entry).unwrap(),
        SaveCacheEntry::Saved
    ));
    assert!(matches!(
        save_cache_entry(&directory, &first, &entry),
        Err(CacheError::RunCollision(_))
    ));
    assert!(matches!(
        save_cache_entry(&directory, &second, &entry),
        Err(CacheError::InconsistentMetadata { .. })
    ));
}

#[test]
fn run_lifecycle_transitions_require_exact_ownership() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let key = compute_run_cache_key("owned-run");
    save_cache_entry(&directory, &key, &run_entry("owned-run", RunState::Pending)).unwrap();
    assert!(matches!(
        run_storage::activate(&directory, &key, "wrong", 100, 200),
        Err(CacheError::InvalidRunTransition(_))
    ));
    let running = run_storage::activate(&directory, &key, "owned-run", 100, 200).unwrap();
    assert_eq!(running.state, RunState::Running);
    assert_eq!(running.child_pid, Some(200));
    assert!(matches!(
        run_storage::finish(&directory, &key, "owned-run", 100, 201),
        Err(CacheError::InvalidRunTransition(_))
    ));
    let claimed = run_storage::finish(&directory, &key, "owned-run", 100, 200).unwrap();
    assert_eq!(claimed.state, RunState::CleanupPending);
    assert!(delete_run_after_cleanup(&directory, &key, &claimed).unwrap());
    assert!(load_cache_entry(&directory, &key).unwrap().is_none());
}

#[test]
fn abandoned_transition_rejects_a_stale_snapshot() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let key = compute_run_cache_key("abandoned");
    save_cache_entry(&directory, &key, &run_entry("abandoned", RunState::Pending)).unwrap();
    let CacheEntry::Run(snapshot) = load_cache_entry(&directory, &key).unwrap().unwrap() else {
        panic!("expected run entry")
    };
    run_storage::activate(&directory, &key, "abandoned", 100, 200).unwrap();
    assert!(matches!(
        claim_abandoned_run(&directory, &key, &snapshot),
        Err(CacheError::InvalidRunTransition(_))
    ));
}

#[test]
fn secrets_are_redacted_and_zeroizing_type_serializes() {
    let entry = base_entry(
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
fn current_cache_schema_is_stable_and_round_trips() {
    let cases = [
        (
            CacheEntry::Base(BaseCacheEntry {
                version: CACHE_SCHEMA_VERSION,
                profile: "developer".into(),
                authority_fingerprint: "authority".into(),
                github_user: "octocat".into(),
                expires_at: TokenExpiry::parse("2026-08-09T11:00:00Z").unwrap(),
                access_token: "base-token".into(),
            }),
            r#"{"kind":"base","version":5,"profile":"developer","authority_fingerprint":"authority","github_user":"octocat","expires_at":"2026-08-09T11:00:00Z","access_token":"base-token"}"#,
        ),
        (
            CacheEntry::Scoped(ScopedCacheEntry {
                version: CACHE_SCHEMA_VERSION,
                profile: "reader".into(),
                source_profile: "developer".into(),
                source_authority_fingerprint: "authority".into(),
                parent_generation: "generation".into(),
                policy_fingerprint: "policy".into(),
                github_user: "octocat".into(),
                repo_scope: "acme/api".into(),
                expires_at: TokenExpiry::parse("2026-08-09T11:00:00Z").unwrap(),
                access_token: "scoped-token".into(),
            }),
            r#"{"kind":"scoped","version":5,"profile":"reader","source_profile":"developer","source_authority_fingerprint":"authority","parent_generation":"generation","policy_fingerprint":"policy","github_user":"octocat","repo_scope":"acme/api","expires_at":"2026-08-09T11:00:00Z","access_token":"scoped-token"}"#,
        ),
        (
            CacheEntry::Run(RunCacheEntry {
                version: RUN_CACHE_SCHEMA_VERSION,
                run_id: "run-1".into(),
                state: RunState::Running,
                wrapper_pid: 100,
                child_pid: Some(101),
                command: "cargo test".into(),
                profile: "reader".into(),
                source_profile: "developer".into(),
                source_authority_fingerprint: "authority".into(),
                github_user: "octocat".into(),
                repo_scope: "acme/api".into(),
                expires_at: TokenExpiry::parse("2026-08-09T11:00:00Z").unwrap(),
                access_token: "run-token".into(),
            }),
            r#"{"kind":"run","version":3,"run_id":"run-1","state":"running","wrapper_pid":100,"child_pid":101,"command":"cargo test","profile":"reader","source_profile":"developer","source_authority_fingerprint":"authority","github_user":"octocat","repo_scope":"acme/api","expires_at":"2026-08-09T11:00:00Z","access_token":"run-token"}"#,
        ),
    ];

    // Intentional structural changes require a schema-version bump and matching golden update.
    for (entry, golden_json) in cases {
        if matches!(&entry, CacheEntry::Run(_)) {
            assert!(!format!("{entry:?}").contains("cargo test"));
        }
        let serialized = serde_json::to_value(&entry).unwrap();
        let golden: serde_json::Value = serde_json::from_str(golden_json).unwrap();
        assert_eq!(serialized, golden);
        assert_eq!(
            serde_json::from_value::<CacheEntry>(serialized).unwrap(),
            entry
        );
    }
}

#[test]
fn unsupported_schemas_fail_closed_and_are_not_overwritten() {
    let cases = [
        (
            base_key(),
            r#"{"kind":"base","version":3,"profile":"developer","authority_fingerprint":"authority","github_user":"octocat","issued_at":"2026-08-09T10:00:00Z","expires_at":"2026-08-09T11:00:00Z","access_token":"base-token"}"#,
        ),
        (
            compute_cache_key("reader", "acme/api"),
            r#"{"kind":"scoped","version":3,"profile":"reader","source_profile":"developer","source_authority_fingerprint":"authority","parent_generation":"generation","policy_fingerprint":"policy","github_user":"octocat","repo_scope":"acme/api","issued_at":"2026-08-09T10:00:00Z","expires_at":"2026-08-09T11:00:00Z","access_token":"scoped-token"}"#,
        ),
        (
            compute_run_cache_key("run-1"),
            r#"{"kind":"run","version":2,"run_id":"run-1","state":"running","wrapper_pid":100,"child_pid":101,"profile":"reader","source_profile":"developer","source_authority_fingerprint":"authority","github_user":"octocat","repo_scope":"acme/api","expires_at":"2026-08-09T11:00:00Z","access_token":"run-token"}"#,
        ),
        (
            base_key(),
            r#"{"kind":"base","profile":"developer","authority_fingerprint":"authority","github_user":"octocat","expires_at":"2026-08-09T11:00:00Z","access_token":"base-token"}"#,
        ),
    ];

    for (key, json) in cases {
        let temp = cache_dir();
        let directory = temp.path().join("cache");
        ensure_cache_dir(&directory).unwrap();
        let path = cache_file_path(&directory, &key);
        let mut file = create_private_tempfile(&directory).unwrap();
        file.write_all(json.as_bytes()).unwrap();
        file.persist(&path).unwrap();

        assert!(matches!(
            load_cache_entry(&directory, &key),
            Err(CacheError::UnsupportedSchema { .. })
        ));
        let before = fs::read(&path).unwrap();
        let replacement = if key == base_key() {
            base_entry(
                "replacement",
                OffsetDateTime::now_utc() + Duration::hours(1),
                "authority",
            )
        } else if key == compute_run_cache_key("run-1") {
            run_entry("run-1", RunState::Running)
        } else {
            scoped_entry(
                "replacement",
                OffsetDateTime::now_utc() + Duration::hours(1),
                "generation",
            )
        };
        assert!(save_cache_entry(&directory, &key, &replacement).is_err());
        assert_eq!(fs::read(path).unwrap(), before);
    }
}

#[test]
fn unknown_cache_kind_uses_the_normal_decoding_error_and_is_retained() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    ensure_cache_dir(&directory).unwrap();
    let key = base_key();
    let path = cache_file_path(&directory, &key);
    let invalid = br#"{"kind":"obsolete","version":5}"#;
    let mut file = create_private_tempfile(&directory).unwrap();
    file.write_all(invalid).unwrap();
    file.persist(&path).unwrap();

    assert!(matches!(
        load_cache_entry(&directory, &key),
        Err(CacheError::Json(_))
    ));
    assert_eq!(fs::read(path).unwrap(), invalid);
}

#[test]
fn save_creates_private_directory_and_entry() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let entry = base_entry(
        "first",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    assert!(matches!(
        save_cache_entry(&directory, &base_key(), &entry).unwrap(),
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
            fs::metadata(cache_file_path(&directory, &base_key()))
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
    let entry = base_entry(
        "token",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    assert!(matches!(
        save_cache_entry(&insecure, &base_key(), &entry),
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

    let entry = base_entry(
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
        save_cache_entry(&symlink_cache, &base_key(), &entry),
        Err(CacheError::InsecurePath { .. })
    ));

    let mode_temp = cache_dir();
    let mode_cache = mode_temp.path().join("cache");
    ensure_cache_dir(&mode_cache).unwrap();
    let mode_lock = mode_cache.join(".cache.lock");
    fs::write(&mode_lock, b"").unwrap();
    fs::set_permissions(&mode_lock, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        save_cache_entry(&mode_cache, &base_key(), &entry),
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
        save_cache_entry(&hard_link_cache, &base_key(), &entry),
        Err(CacheError::InsecurePath { .. })
    ));
}

#[test]
fn malformed_entry_is_never_overwritten() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    ensure_cache_dir(&directory).unwrap();
    let path = cache_file_path(&directory, &base_key());
    let mut file = create_private_tempfile(&directory).unwrap();
    file.write_all(b"{ malformed").unwrap();
    file.persist(&path).unwrap();
    let replacement = base_entry(
        "replacement",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    assert!(matches!(
        save_cache_entry(&directory, &base_key(), &replacement),
        Err(CacheError::Json(_))
    ));
    assert_eq!(fs::read_to_string(path).unwrap(), "{ malformed");
}

#[test]
fn malformed_current_expiry_is_not_discarded_or_overwritten() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    ensure_cache_dir(&directory).unwrap();
    let path = cache_file_path(&directory, &base_key());
    let invalid = r#"{
        "kind":"base",
        "version":5,
        "profile":"developer",
        "authority_fingerprint":"authority",
        "github_user":"octocat",
        "expires_at":"invalid",
        "access_token":"existing"
    }"#;
    let mut file = create_private_tempfile(&directory).unwrap();
    file.write_all(invalid.as_bytes()).unwrap();
    file.persist(&path).unwrap();
    assert!(matches!(
        load_cache_entry(&directory, &base_key()),
        Err(CacheError::Json(_))
    ));
    let replacement = base_entry(
        "replacement",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    assert!(matches!(
        save_cache_entry(&directory, &base_key(), &replacement),
        Err(CacheError::Json(_))
    ));
    assert_eq!(fs::read_to_string(path).unwrap(), invalid);
}

#[test]
fn compatible_entry_is_retained_and_wrong_kind_fails_closed() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let existing = base_entry(
        "existing",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "same",
    );
    let candidate = base_entry(
        "candidate",
        OffsetDateTime::now_utc() + Duration::hours(2),
        "same",
    );
    save_cache_entry(&directory, &base_key(), &existing).unwrap();
    let retained = save_cache_entry(&directory, &base_key(), &candidate).unwrap();
    match retained {
        SaveCacheEntry::Retained(entry) => match *entry {
            CacheEntry::Base(BaseCacheEntry { access_token, .. }) => {
                assert_eq!(access_token.as_ref(), "existing");
            }
            CacheEntry::Scoped(_) | CacheEntry::Run(_) => {
                panic!("expected retained base entry")
            }
        },
        SaveCacheEntry::Saved => panic!("expected compatible entry to be retained"),
    }

    let other = temp.path().join("other");
    let scoped = CacheEntry::Scoped(ScopedCacheEntry {
        version: CACHE_SCHEMA_VERSION,
        profile: "developer".into(),
        source_profile: "developer".into(),
        source_authority_fingerprint: "authority".into(),
        parent_generation: "parent".into(),
        policy_fingerprint: "policy".into(),
        github_user: "octocat".into(),
        repo_scope: "all".into(),
        expires_at: TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(1)),
        access_token: "scoped".into(),
    });
    save_cache_entry(&other, &base_key(), &scoped).unwrap();
    assert!(matches!(
        save_cache_entry(&other, &base_key(), &candidate),
        Err(CacheError::UnexpectedKind { .. })
    ));
}

#[test]
fn inconsistent_embedded_key_metadata_fails_closed() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let wrong_key = compute_cache_key("different", "all");
    let entry = base_entry(
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
    let first = base_entry(
        "first",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    let second = base_entry(
        "second",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    let handles = [first, second].map(|entry| {
        let directory = Arc::clone(&directory);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            save_cache_entry(&directory, &base_key(), &entry).unwrap()
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
