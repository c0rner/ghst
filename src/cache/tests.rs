use crate::cache::error::CacheError;
use crate::cache::key::{compute_cache_key, compute_run_cache_key};
use crate::cache::storage::{delete_cache_entry, load_cache_entry, write_test_entry};
use crate::cache::store::CacheStore;
use crate::cache::types::{
    BaseCacheEntryDto, CacheEntryDto, Record, RecordWriteView, RunCacheEntryDto,
    ScopedCacheEntryDto,
};
use crate::cache::{cache_file_path, ensure_cache_dir};
use crate::credential::store::{
    CommitBaseOutcome, DeleteBaseOutcome, IssuanceGuard, IssuanceGuardStore, ReadCredentials,
    ReplaceOutcome, SourceGuard, WriteCredentials,
};
use crate::credential::{BaseCredential, ScopedCredential, TokenExpiry};
use crate::fs::create_private_tempfile;
use crate::run::store::{PendingRunOutcome, PendingRunStore, RunLifecycleStore};
use crate::run::{RunRecord, RunState};
use std::fs;
use std::io::Write;
use std::sync::{Arc, Barrier};
use std::thread;
use time::{Duration, OffsetDateTime};

fn base_key() -> String {
    compute_cache_key("developer", "all")
}

fn base_credential(token: &str, expiry: OffsetDateTime, authority: &str) -> BaseCredential {
    BaseCredential {
        profile: "developer".into(),
        authority_fingerprint: authority.into(),
        github_user: "octocat".into(),
        expires_at: TokenExpiry::new(expiry),
        access_token: token.into(),
    }
}

fn base_entry(token: &str, expiry: OffsetDateTime, authority: &str) -> Record {
    Record::Base(base_credential(token, expiry, authority))
}

fn scoped_credential(
    token: &str,
    expiry: OffsetDateTime,
    parent_generation: &str,
) -> ScopedCredential {
    ScopedCredential {
        profile: "reader".into(),
        source_profile: "developer".into(),
        source_authority_fingerprint: "authority".into(),
        parent_generation: parent_generation.into(),
        policy_fingerprint: "policy".into(),
        github_user: "octocat".into(),
        repo_scope: "acme/api".into(),
        expires_at: TokenExpiry::new(expiry),
        access_token: token.into(),
    }
}

fn scoped_entry(token: &str, expiry: OffsetDateTime, parent_generation: &str) -> Record {
    Record::Scoped(scoped_credential(token, expiry, parent_generation))
}

fn cache_dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn run_record(run_id: &str, state: RunState) -> RunRecord {
    RunRecord {
        run_id: run_id.into(),
        state,
        wrapper_pid: 100,
        child_pid: None,
        command: "echo test".into(),
        profile: "reader".into(),
        source_profile: "developer".into(),
        source_authority_fingerprint: "authority".into(),
        github_user: "octocat".into(),
        repo_scope: "acme/api".into(),
        expires_at: TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(1)),
        access_token: "run-token".into(),
    }
}

fn run_entry(run_id: &str, state: RunState) -> Record {
    Record::Run(run_record(run_id, state))
}

fn write_raw_test_entry(cache_dir: &std::path::Path, hash_key: &str, entry: &Record) {
    ensure_cache_dir(cache_dir).unwrap();
    let write_view = RecordWriteView::from(entry);
    let json_bytes = serde_json::to_vec_pretty(&write_view).unwrap();
    crate::fs::publish_replacement(&cache_file_path(cache_dir, hash_key), &json_bytes).unwrap();
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
    let store = CacheStore::new(&directory);
    let now = OffsetDateTime::now_utc();
    let rejected = base_entry("rejected", now + Duration::hours(1), "authority");
    let Record::Base(rejected_data) = &rejected else {
        panic!("expected base")
    };
    let rejected_generation = rejected_data.generation_fingerprint();
    write_test_entry(&directory, &base_key(), &rejected).unwrap();

    assert_eq!(
        store
            .delete_base_if_generation("developer", &rejected_generation)
            .unwrap(),
        DeleteBaseOutcome::Deleted
    );
    assert!(store.read_base("developer").unwrap().is_none());
    assert_eq!(
        store
            .delete_base_if_generation("developer", &rejected_generation)
            .unwrap(),
        DeleteBaseOutcome::Missing
    );

    let replacement = base_entry("replacement", now + Duration::hours(1), "authority");
    write_test_entry(&directory, &base_key(), &replacement).unwrap();
    assert_eq!(
        store
            .delete_base_if_generation("developer", &rejected_generation)
            .unwrap(),
        DeleteBaseOutcome::Changed
    );
    assert_eq!(
        store
            .read_base("developer")
            .unwrap()
            .unwrap()
            .access_token
            .as_ref(),
        "replacement"
    );
}

#[test]
fn renewal_compare_and_replace_returns_the_exact_displaced_entry() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let store = CacheStore::new(&directory);
    let now = OffsetDateTime::now_utc();
    let base = base_entry("base", now + Duration::hours(1), "authority");
    let Record::Base(base_data) = &base else {
        panic!("expected base")
    };
    let generation = base_data.generation_fingerprint();
    write_test_entry(&directory, &base_key(), &base).unwrap();
    let key = compute_cache_key("reader", "acme/api");
    let selected_entry = scoped_entry("selected", now + Duration::minutes(5), &generation);
    write_test_entry(&directory, &key, &selected_entry).unwrap();
    let selected = scoped_credential("selected", now + Duration::minutes(5), &generation);
    let candidate = scoped_credential("candidate", now + Duration::hours(1), &generation);
    let guard = store.issuance_guard().unwrap();
    let source_guard = SourceGuard::new("developer", &generation);

    let result = store
        .renew_scoped(&selected, &candidate, guard, &source_guard, now)
        .unwrap();

    let ReplaceOutcome::Replaced(displaced) = result else {
        panic!("expected replacement")
    };
    assert_eq!(displaced.access_token.as_ref(), "selected");
    assert_eq!(
        store
            .read_scoped("reader", "acme/api")
            .unwrap()
            .unwrap()
            .access_token
            .as_ref(),
        "candidate"
    );
}

#[test]
fn renewal_compare_and_replace_retains_a_compatible_concurrent_winner() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let store = CacheStore::new(&directory);
    let now = OffsetDateTime::now_utc();
    let base = base_entry("base", now + Duration::hours(1), "authority");
    let Record::Base(base_data) = &base else {
        panic!("expected base")
    };
    let generation = base_data.generation_fingerprint();
    write_test_entry(&directory, &base_key(), &base).unwrap();
    let key = compute_cache_key("reader", "acme/api");
    let selected_entry = scoped_entry("selected", now + Duration::minutes(5), &generation);
    write_test_entry(&directory, &key, &selected_entry).unwrap();
    let selected = scoped_credential("selected", now + Duration::minutes(5), &generation);
    let guard = store.issuance_guard().unwrap();
    delete_cache_entry(&directory, &key).unwrap();
    let winner_entry = scoped_entry("winner", now + Duration::hours(1), &generation);
    write_test_entry(&directory, &key, &winner_entry).unwrap();
    let candidate = scoped_credential("candidate", now + Duration::hours(1), &generation);
    let source_guard = SourceGuard::new("developer", &generation);

    let result = store
        .renew_scoped(&selected, &candidate, guard, &source_guard, now)
        .unwrap();

    let ReplaceOutcome::Retained(retained) = result else {
        panic!("expected retained winner")
    };
    assert_eq!(retained.access_token.as_ref(), "winner");
}

#[test]
fn run_keys_are_unique_domain_separated_and_reject_collisions() {
    let first = compute_run_cache_key("first");
    let second = compute_run_cache_key("second");
    assert_ne!(first, second);
    assert_ne!(first, compute_cache_key("run", "first"));

    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let store = CacheStore::new(&directory);
    let now = OffsetDateTime::now_utc();
    let base = base_entry("base", now + Duration::hours(1), "authority");
    let Record::Base(base_data) = &base else {
        panic!("expected base")
    };
    let generation = base_data.generation_fingerprint();
    write_test_entry(&directory, &base_key(), &base).unwrap();
    let source_guard = SourceGuard::new("developer", &generation);

    let run = run_record("first", RunState::Pending);
    let guard = store.issuance_guard().unwrap();
    assert_eq!(
        store.commit_pending(&run, guard, &source_guard).unwrap(),
        PendingRunOutcome::Saved
    );
    let guard2 = store.issuance_guard().unwrap();
    assert!(matches!(
        store.commit_pending(&run, guard2, &source_guard),
        Err(CacheError::RunCollision(_))
    ));
}

#[test]
fn run_lifecycle_transitions_require_exact_ownership() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let store = CacheStore::new(&directory);
    let key = compute_run_cache_key("owned-run");
    write_test_entry(&directory, &key, &run_entry("owned-run", RunState::Pending)).unwrap();
    assert!(matches!(
        store.activate("wrong", 100, 200),
        Err(CacheError::InvalidRunTransition(_))
    ));
    let running = store.activate("owned-run", 100, 200).unwrap();
    assert_eq!(running.state, RunState::Running);
    assert_eq!(running.child_pid, Some(200));
    assert!(matches!(
        store.finish("owned-run", 100, 201),
        Err(CacheError::InvalidRunTransition(_))
    ));
    let claimed = store.finish("owned-run", 100, 200).unwrap();
    assert_eq!(claimed.state, RunState::CleanupPending);
    assert!(store.delete_cleanup_pending(&claimed).unwrap());
    assert!(load_cache_entry(&directory, &key).unwrap().is_none());
}

#[test]
fn abandoned_transition_rejects_a_stale_snapshot() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let store = CacheStore::new(&directory);
    let key = compute_run_cache_key("abandoned");
    write_test_entry(&directory, &key, &run_entry("abandoned", RunState::Pending)).unwrap();
    let Record::Run(snapshot) = load_cache_entry(&directory, &key).unwrap().unwrap() else {
        panic!("expected run entry")
    };
    store.activate("abandoned", 100, 200).unwrap();
    assert!(matches!(
        store.claim_abandoned(&snapshot),
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
    let json = serde_json::to_string(&RecordWriteView::from(&entry)).unwrap();
    assert!(json.contains("ghu_secret_123456"));
    let dto: CacheEntryDto = serde_json::from_str(&json).unwrap();
    let restored: Record = Record::try_from(dto).unwrap();
    assert_eq!(restored, entry);
}

#[test]
fn current_cache_schema_is_stable_and_round_trips() {
    let cases = [
        (
            Record::Base(BaseCredential {
                profile: "developer".into(),
                authority_fingerprint: "authority".into(),
                github_user: "octocat".into(),
                expires_at: TokenExpiry::parse("2026-08-09T11:00:00Z").unwrap(),
                access_token: "base-token".into(),
            }),
            r#"{"kind":"base","version":5,"profile":"developer","authority_fingerprint":"authority","github_user":"octocat","expires_at":"2026-08-09T11:00:00Z","access_token":"base-token"}"#,
        ),
        (
            Record::Scoped(ScopedCredential {
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
            Record::Run(RunRecord {
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
        if matches!(&entry, Record::Run(_)) {
            assert!(!format!("{entry:?}").contains("cargo test"));
        }
        let serialized = serde_json::to_value(RecordWriteView::from(&entry)).unwrap();
        let golden: serde_json::Value = serde_json::from_str(golden_json).unwrap();
        assert_eq!(serialized, golden);
        let decoded: CacheEntryDto = serde_json::from_value(serialized).unwrap();
        assert_eq!(Record::try_from(decoded).unwrap(), entry);
    }
}

#[test]
fn dto_conversion_rejects_unsupported_versions_with_valid_fields() {
    // Unsupported schema versions with otherwise valid fields are rejected at the DTO conversion boundary.
    let invalid_version_cases = [
        (
            r#"{"kind":"base","version":4,"profile":"developer","authority_fingerprint":"authority","github_user":"octocat","expires_at":"2026-08-09T11:00:00Z","access_token":"base-token"}"#,
            "base",
            4,
            5,
        ),
        (
            r#"{"kind":"base","version":6,"profile":"developer","authority_fingerprint":"authority","github_user":"octocat","expires_at":"2026-08-09T11:00:00Z","access_token":"base-token"}"#,
            "base",
            6,
            5,
        ),
        (
            r#"{"kind":"scoped","version":4,"profile":"reader","source_profile":"developer","source_authority_fingerprint":"authority","parent_generation":"generation","policy_fingerprint":"policy","github_user":"octocat","repo_scope":"acme/api","expires_at":"2026-08-09T11:00:00Z","access_token":"scoped-token"}"#,
            "scoped",
            4,
            5,
        ),
        (
            r#"{"kind":"scoped","version":6,"profile":"reader","source_profile":"developer","source_authority_fingerprint":"authority","parent_generation":"generation","policy_fingerprint":"policy","github_user":"octocat","repo_scope":"acme/api","expires_at":"2026-08-09T11:00:00Z","access_token":"scoped-token"}"#,
            "scoped",
            6,
            5,
        ),
        (
            r#"{"kind":"run","version":2,"run_id":"run-1","state":"running","wrapper_pid":100,"child_pid":101,"command":"cargo test","profile":"reader","source_profile":"developer","source_authority_fingerprint":"authority","github_user":"octocat","repo_scope":"acme/api","expires_at":"2026-08-09T11:00:00Z","access_token":"run-token"}"#,
            "run",
            2,
            3,
        ),
        (
            r#"{"kind":"run","version":4,"run_id":"run-1","state":"running","wrapper_pid":100,"child_pid":101,"command":"cargo test","profile":"reader","source_profile":"developer","source_authority_fingerprint":"authority","github_user":"octocat","repo_scope":"acme/api","expires_at":"2026-08-09T11:00:00Z","access_token":"run-token"}"#,
            "run",
            4,
            3,
        ),
    ];

    for (json, expected_kind, actual_version, expected_version) in invalid_version_cases {
        let decoded: CacheEntryDto = serde_json::from_str(json).unwrap();
        let err = Record::try_from(decoded).unwrap_err();
        assert!(matches!(
            err,
            CacheError::UnsupportedSchema {
                ref kind,
                version: Some(v),
                expected,
            } if kind == expected_kind && v == actual_version && expected == expected_version
        ));
    }

    // Direct DTO conversion also enforces schema version validation.
    let base_dto: BaseCacheEntryDto = serde_json::from_str(
        r#"{"version":4,"profile":"developer","authority_fingerprint":"authority","github_user":"octocat","expires_at":"2026-08-09T11:00:00Z","access_token":"base-token"}"#,
    )
    .unwrap();
    assert!(matches!(
        BaseCredential::try_from(base_dto),
        Err(CacheError::UnsupportedSchema {
            version: Some(4),
            expected: 5,
            ..
        })
    ));

    let scoped_dto: ScopedCacheEntryDto = serde_json::from_str(
        r#"{"version":4,"profile":"reader","source_profile":"developer","source_authority_fingerprint":"authority","parent_generation":"generation","policy_fingerprint":"policy","github_user":"octocat","repo_scope":"acme/api","expires_at":"2026-08-09T11:00:00Z","access_token":"scoped-token"}"#,
    )
    .unwrap();
    assert!(matches!(
        ScopedCredential::try_from(scoped_dto),
        Err(CacheError::UnsupportedSchema {
            version: Some(4),
            expected: 5,
            ..
        })
    ));

    let run_dto: RunCacheEntryDto = serde_json::from_str(
        r#"{"version":2,"run_id":"run-1","state":"running","wrapper_pid":100,"child_pid":101,"command":"cargo test","profile":"reader","source_profile":"developer","source_authority_fingerprint":"authority","github_user":"octocat","repo_scope":"acme/api","expires_at":"2026-08-09T11:00:00Z","access_token":"run-token"}"#,
    )
    .unwrap();
    assert!(matches!(
        RunRecord::try_from(run_dto),
        Err(CacheError::UnsupportedSchema {
            version: Some(2),
            expected: 3,
            ..
        })
    ));
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
        let store = CacheStore::new(&directory);
        let guard = store.issuance_guard().unwrap();
        let base_data = base_entry(
            "base",
            OffsetDateTime::now_utc() + Duration::hours(1),
            "authority",
        );
        let Record::Base(ref base) = base_data else {
            unreachable!()
        };
        let generation = base.generation_fingerprint();
        if key != base_key() {
            write_test_entry(&directory, &base_key(), &base_data).unwrap();
        }

        if key == base_key() {
            let replacement = base_credential(
                "replacement",
                OffsetDateTime::now_utc() + Duration::hours(1),
                "authority",
            );
            assert!(store.commit_base(&replacement, guard).is_err());
        } else if key == compute_run_cache_key("run-1") {
            let run = run_record("run-1", RunState::Running);
            let source_guard = SourceGuard::new("developer", &generation);
            assert!(store.commit_pending(&run, guard, &source_guard).is_err());
        } else {
            let replacement = scoped_credential(
                "replacement",
                OffsetDateTime::now_utc() + Duration::hours(1),
                &generation,
            );
            let source_guard = SourceGuard::new("developer", &generation);
            assert!(
                store
                    .commit_scoped(&replacement, guard, &source_guard)
                    .is_err()
            );
        }
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
    let store = CacheStore::new(&directory);
    let entry = base_credential(
        "first",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    let guard = store.issuance_guard().unwrap();
    assert_eq!(
        store.commit_base(&entry, guard).unwrap(),
        CommitBaseOutcome::Saved
    );

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
    let store = CacheStore::new(&insecure);
    let entry = base_credential(
        "token",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    assert!(matches!(
        store.commit_base(&entry, IssuanceGuard::new(0)),
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
fn delete_exact_record_rejects_insecure_target() {
    use crate::token::store::DeleteInspectedRecord;
    use std::os::unix::fs::symlink;

    let temp = cache_dir();
    let directory = temp.path().join("cache");
    ensure_cache_dir(&directory).unwrap();
    let key = base_key();
    let path = cache_file_path(&directory, &key);
    let target = temp.path().join("target");
    fs::write(&target, b"target").unwrap();
    symlink(&target, &path).unwrap();

    let store = CacheStore::new(&directory);
    let entry = base_entry(
        "token",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    assert!(matches!(
        store.delete_exact_record(&key, &entry),
        Err(CacheError::InsecurePath { .. })
    ));
    assert!(path.symlink_metadata().is_ok());
}

#[cfg(unix)]
#[test]
fn insecure_global_lock_file_fails_closed() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let entry = base_credential(
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
        CacheStore::new(&symlink_cache).commit_base(&entry, IssuanceGuard::new(0)),
        Err(CacheError::InsecurePath { .. })
    ));

    let mode_temp = cache_dir();
    let mode_cache = mode_temp.path().join("cache");
    ensure_cache_dir(&mode_cache).unwrap();
    let mode_lock = mode_cache.join(".cache.lock");
    fs::write(&mode_lock, b"").unwrap();
    fs::set_permissions(&mode_lock, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        CacheStore::new(&mode_cache).commit_base(&entry, IssuanceGuard::new(0)),
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
        CacheStore::new(&hard_link_cache).commit_base(&entry, IssuanceGuard::new(0)),
        Err(CacheError::InsecurePath { .. })
    ));
}

#[test]
fn malformed_entry_is_never_overwritten() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let store = CacheStore::new(&directory);
    ensure_cache_dir(&directory).unwrap();
    let path = cache_file_path(&directory, &base_key());
    let mut file = create_private_tempfile(&directory).unwrap();
    file.write_all(b"{ malformed").unwrap();
    file.persist(&path).unwrap();
    let replacement = base_credential(
        "replacement",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    let guard = store.issuance_guard().unwrap();
    assert!(matches!(
        store.commit_base(&replacement, guard),
        Err(CacheError::Json(_))
    ));
    assert_eq!(fs::read_to_string(path).unwrap(), "{ malformed");
}

#[test]
fn malformed_current_expiry_is_not_discarded_or_overwritten() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let store = CacheStore::new(&directory);
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
    let replacement = base_credential(
        "replacement",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    let guard = store.issuance_guard().unwrap();
    assert!(matches!(
        store.commit_base(&replacement, guard),
        Err(CacheError::Json(_))
    ));
    assert_eq!(fs::read_to_string(path).unwrap(), invalid);
}

#[test]
fn compatible_entry_is_retained_and_wrong_kind_fails_closed() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let store = CacheStore::new(&directory);
    let existing = base_credential(
        "existing",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "same",
    );
    let candidate = base_credential(
        "candidate",
        OffsetDateTime::now_utc() + Duration::hours(2),
        "same",
    );
    let guard1 = store.issuance_guard().unwrap();
    assert_eq!(
        store.commit_base(&existing, guard1).unwrap(),
        CommitBaseOutcome::Saved
    );
    let guard2 = store.issuance_guard().unwrap();
    let retained = store.commit_base(&candidate, guard2).unwrap();
    match retained {
        CommitBaseOutcome::Retained(entry) => {
            assert_eq!(entry.access_token.as_ref(), "existing");
        }
        other => panic!("expected compatible entry to be retained, got {other:?}"),
    }

    let other = temp.path().join("other");
    let other_store = CacheStore::new(&other);
    let scoped = Record::Scoped(ScopedCredential {
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
    write_test_entry(&other, &base_key(), &scoped).unwrap();
    let guard3 = other_store.issuance_guard().unwrap();
    assert!(matches!(
        other_store.commit_base(&candidate, guard3),
        Err(CacheError::UnexpectedKind { .. })
    ));
}

#[test]
fn inconsistent_embedded_key_metadata_fails_closed() {
    let temp = cache_dir();
    let directory = temp.path().join("cache");
    ensure_cache_dir(&directory).unwrap();
    let store = CacheStore::new(&directory);

    // 1. Base entry with inconsistent profile metadata
    let wrong_base_key = compute_cache_key("different", "all");
    let base = base_entry(
        "token",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    write_raw_test_entry(&directory, &wrong_base_key, &base);
    assert!(matches!(
        store.read_base("different"),
        Err(CacheError::InconsistentMetadata { .. })
    ));

    // 2. Scoped entry with inconsistent repo_scope metadata
    let scoped = scoped_entry(
        "scoped-token",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "gen-1",
    );
    let wrong_scoped_key = compute_cache_key("reader", "acme/other");
    write_raw_test_entry(&directory, &wrong_scoped_key, &scoped);
    assert!(matches!(
        store.read_scoped("reader", "acme/other"),
        Err(CacheError::InconsistentMetadata { .. })
    ));
}

#[test]
fn concurrent_saves_retain_one_compatible_winner() {
    let temp = cache_dir();
    let directory = Arc::new(temp.path().join("cache"));
    let barrier = Arc::new(Barrier::new(2));
    let first = base_credential(
        "first",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    let second = base_credential(
        "second",
        OffsetDateTime::now_utc() + Duration::hours(1),
        "authority",
    );
    let handles = [first, second].map(|candidate| {
        let directory = Arc::clone(&directory);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let store = CacheStore::new(&*directory);
            let guard = store.issuance_guard().unwrap();
            barrier.wait();
            store.commit_base(&candidate, guard).unwrap()
        })
    });
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, CommitBaseOutcome::Saved))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, CommitBaseOutcome::Retained(_)))
            .count(),
        1
    );
}

#[test]
fn epoch_advance_during_revocation_rejects_stale_issuance_and_renewal() {
    use crate::cache::store::CacheStore;
    use crate::credential::store::{
        CommitBaseOutcome, CommitScopedOutcome, IssuanceGuardStore, ReplaceOutcome, SourceGuard,
        WriteCredentials,
    };
    use crate::run::store::{PendingRunOutcome, PendingRunStore};
    use crate::token::store::{BeginRevocation, RevocationSelection};

    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let store = CacheStore::new(&directory);
    let now = OffsetDateTime::now_utc();

    let base = base_entry("base-token", now + Duration::hours(1), "authority");
    let Record::Base(base_data) = &base else {
        panic!("expected base")
    };
    let generation = base_data.generation_fingerprint();
    write_test_entry(&directory, &base_key(), &base).unwrap();

    let scoped_key = compute_cache_key("reader", "acme/api");
    let existing_scoped = scoped_entry("scoped-old", now + Duration::minutes(5), &generation);
    write_test_entry(&directory, &scoped_key, &existing_scoped).unwrap();
    let Record::Scoped(existing_scoped_data) = &existing_scoped else {
        panic!("expected scoped")
    };

    let guard = store.issuance_guard().unwrap();
    assert!(matches!(
        store.begin_revocation(RevocationSelection::All).unwrap(),
        crate::token::store::RevocationBatch::Selected(_)
    ));

    let new_base = base_credential("new-base-token", now + Duration::hours(2), "authority");
    assert_eq!(
        store.commit_base(&new_base, guard).unwrap(),
        CommitBaseOutcome::EpochChanged
    );
    assert_eq!(
        load_cache_entry(&directory, &base_key())
            .unwrap()
            .unwrap()
            .access_token()
            .as_ref(),
        "base-token"
    );

    let new_scoped = scoped_credential("new-scoped-token", now + Duration::hours(2), &generation);
    let source_guard = SourceGuard {
        source_profile: "developer",
        expected_generation: &generation,
    };
    assert_eq!(
        store
            .commit_scoped(&new_scoped, guard, &source_guard)
            .unwrap(),
        CommitScopedOutcome::EpochChanged
    );

    let renewal_outcome = store
        .renew_scoped(existing_scoped_data, &new_scoped, guard, &source_guard, now)
        .unwrap();
    assert_eq!(renewal_outcome, ReplaceOutcome::EpochChanged);
    assert_eq!(
        load_cache_entry(&directory, &scoped_key)
            .unwrap()
            .unwrap()
            .access_token()
            .as_ref(),
        "scoped-old"
    );

    let run = run_record("run-stale", RunState::Pending);
    assert_eq!(
        store.commit_pending(&run, guard, &source_guard).unwrap(),
        PendingRunOutcome::EpochChanged
    );
    assert!(
        load_cache_entry(&directory, &compute_run_cache_key("run-stale"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn revocation_selection_behavior_and_epoch_advance() {
    use crate::cache::store::CacheStore;
    use crate::credential::store::IssuanceGuardStore;
    use crate::token::store::{BeginRevocation, RevocationBatch, RevocationSelection};

    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let store = CacheStore::new(&directory);
    let now = OffsetDateTime::now_utc();

    let base = base_entry("base-token", now + Duration::hours(1), "authority");
    write_test_entry(&directory, &base_key(), &base).unwrap();

    let initial_epoch = store.issuance_guard().unwrap();

    let batch = store
        .begin_revocation(RevocationSelection::One(
            &base_key()[..crate::cache::MIN_CACHE_ID_LENGTH],
        ))
        .unwrap();
    let RevocationBatch::Selected(items) = batch else {
        panic!("expected selected")
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].slot_id.as_deref(), Some(base_key().as_str()));

    let after_first_epoch = store.issuance_guard().unwrap();
    assert!(after_first_epoch.value() > initial_epoch.value());

    let batch = store
        .begin_revocation(RevocationSelection::One("ffffffffffffffff"))
        .unwrap();
    assert!(matches!(batch, RevocationBatch::NotFound));

    let after_second_epoch = store.issuance_guard().unwrap();
    assert!(after_second_epoch.value() > after_first_epoch.value());

    let first = format!("0123456{}", "a".repeat(57));
    let second = format!("0123456{}", "b".repeat(57));
    fs::write(
        directory.join(format!("{first}.json")),
        b"{\"invalid\": true}",
    )
    .unwrap();
    fs::write(directory.join(format!("{second}.json")), b"corrupt").unwrap();

    let batch = store
        .begin_revocation(RevocationSelection::One("0123456"))
        .unwrap();
    assert!(matches!(batch, RevocationBatch::Ambiguous));
    assert!(directory.join(format!("{first}.json")).exists());
    assert!(directory.join(format!("{second}.json")).exists());

    let after_third_epoch = store.issuance_guard().unwrap();
    assert!(after_third_epoch.value() > after_second_epoch.value());
}

#[test]
fn exact_record_deletion_distinguishes_deleted_missing_and_changed() {
    use crate::cache::store::CacheStore;
    use crate::token::store::{DeleteInspectedRecord, DeleteOutcome, Record as TokenRecord};

    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let store = CacheStore::new(&directory);
    let now = OffsetDateTime::now_utc();

    let entry = base_entry("token-1", now + Duration::hours(1), "authority");
    write_test_entry(&directory, &base_key(), &entry).unwrap();

    let expected = TokenRecord::Base(base_credential(
        "token-1",
        now + Duration::hours(1),
        "authority",
    ));
    assert!(matches!(
        store.delete_exact_record(&base_key(), &expected).unwrap(),
        DeleteOutcome::Deleted
    ));
    assert!(matches!(
        store.delete_exact_record(&base_key(), &expected).unwrap(),
        DeleteOutcome::Missing
    ));

    let new_entry = base_entry("token-2", now + Duration::hours(2), "authority");
    write_test_entry(&directory, &base_key(), &new_entry).unwrap();

    assert!(matches!(
        store.delete_exact_record(&base_key(), &expected).unwrap(),
        DeleteOutcome::Changed
    ));
    assert!(load_cache_entry(&directory, &base_key()).unwrap().is_some());
}

#[test]
fn source_base_validation_rejects_inconsistent_metadata_and_unexpected_kind() {
    use crate::cache::store::CacheStore;
    use crate::credential::store::{IssuanceGuardStore, SourceGuard, WriteCredentials};

    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let store = CacheStore::new(&directory);
    let now = OffsetDateTime::now_utc();

    let guard = store.issuance_guard().unwrap();
    let source_guard = SourceGuard {
        source_profile: "developer",
        expected_generation: "gen-1",
    };
    let new_scoped = scoped_credential("new-scoped-token", now + Duration::hours(2), "gen-1");

    // Case 1: Base slot contains a base record with inconsistent profile metadata
    let bad_base = base_entry("token", now + Duration::hours(1), "authority");
    let Record::Base(mut bad_base_record) = bad_base else {
        unreachable!()
    };
    bad_base_record.profile = "other_prof".into();
    write_raw_test_entry(&directory, &base_key(), &Record::Base(bad_base_record));
    assert!(matches!(
        store.commit_scoped(&new_scoped, guard, &source_guard),
        Err(CacheError::InconsistentMetadata { .. })
    ));

    // Case 2: Base slot contains a Scoped record instead of a Base record
    let Record::Scoped(mut scoped_record) =
        scoped_entry("token", now + Duration::hours(1), "gen-1")
    else {
        unreachable!()
    };
    scoped_record.profile = "developer".into();
    scoped_record.repo_scope = "all".into();
    write_raw_test_entry(&directory, &base_key(), &Record::Scoped(scoped_record));
    assert!(matches!(
        store.commit_scoped(&new_scoped, guard, &source_guard),
        Err(CacheError::UnexpectedKind {
            expected: "base",
            actual: "scoped"
        })
    ));
}

#[test]
fn cache_store_exact_record_deletion_maps_directory_sync_failure() {
    use crate::cache::store::CacheStore;
    use crate::token::store::{DeleteOutcome, Record as TokenRecord};

    let temp = cache_dir();
    let directory = temp.path().join("cache");
    let store = CacheStore::new(&directory);
    let now = OffsetDateTime::now_utc();

    let entry = base_entry("token-1", now + Duration::hours(1), "authority");
    write_test_entry(&directory, &base_key(), &entry).unwrap();

    let expected = TokenRecord::Base(base_credential(
        "token-1",
        now + Duration::hours(1),
        "authority",
    ));
    let outcome = store
        .delete_exact_record_with_sync(&base_key(), &expected, |path| {
            Err(crate::fs::FsError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::other("simulated sync failure"),
            })
        })
        .unwrap();

    assert!(matches!(outcome, DeleteOutcome::UnlinkedSyncFailed(_)));
    assert!(load_cache_entry(&directory, &base_key()).unwrap().is_none());
}
