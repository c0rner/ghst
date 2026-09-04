mod digest;
mod error;
mod fs;
mod key;
pub mod run_storage;
mod storage;
mod types;

#[cfg(test)]
mod tests;

pub use error::CacheError;
pub use fs::cache_epoch;
pub use key::{
    MIN_CACHE_ID_LENGTH, abbreviate_cache_key, compute_cache_key, compute_run_cache_key,
};
pub use storage::{
    CacheInspection, CacheInspectionState, DeleteBaseOutcome, claim_abandoned_run,
    delete_base_if_generation, delete_entry_if_unchanged, delete_run_after_cleanup, inspect_cache,
    load_cache_entry, replace_cache_candidate, revoke_transaction, save_cache_candidate,
};
#[cfg(test)]
pub use storage::{delete_cache_entry, list_all_cache_entries, save_cache_entry};
pub use types::{
    BaseCacheEntry, CACHE_SCHEMA_VERSION, CacheEntry, RUN_CACHE_SCHEMA_VERSION, ReplaceCacheEntry,
    RunCacheEntry, RunState, SaveCacheEntry, ScopedCacheEntry, authority_fingerprint,
    format_rfc3339, policy_fingerprint,
};
