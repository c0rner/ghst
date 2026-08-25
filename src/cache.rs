mod digest;
mod error;
mod fs;
mod key;
mod storage;
mod types;

#[cfg(test)]
mod tests;

pub use error::CacheError;
pub use fs::cache_epoch;
pub use key::{compute_cache_key, compute_run_cache_key};
pub use storage::{
    CacheInspection, CacheInspectionState, DeleteRootOutcome, claim_abandoned_run,
    claim_released_run, delete_entry_if_unchanged, delete_root_if_generation,
    delete_run_after_cleanup, inspect_cache, load_cache_entry, mark_pending_run_for_cleanup,
    replace_cache_candidate, revoke_transaction, save_cache_candidate, transition_run_to_running,
};
#[cfg(test)]
pub use storage::{delete_cache_entry, list_all_cache_entries, save_cache_entry};
pub use types::{
    AccessToken, CACHE_SCHEMA_VERSION, CacheEntry, DerivedCacheEntry, RUN_CACHE_SCHEMA_VERSION,
    ReplaceCacheEntry, RootCacheEntry, RunCacheEntry, RunState, SaveCacheEntry, TokenExpiry,
    authority_fingerprint, format_rfc3339, policy_fingerprint,
};
