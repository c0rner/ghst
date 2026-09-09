mod digest;
mod error;
mod key;
mod lock;
pub mod run_storage;
mod storage;
mod types;

#[cfg(test)]
mod tests;

pub use error::CacheError;
#[cfg(test)]
pub use key::cache_file_path;
pub use key::{
    MIN_CACHE_ID_LENGTH, abbreviate_cache_key, compute_cache_key, compute_run_cache_key,
};
pub use lock::cache_epoch;
#[cfg(test)]
pub use lock::ensure_cache_dir;
pub use storage::{
    CacheInspection, CacheInspectionState, DeleteBaseOutcome, claim_abandoned_run,
    delete_base_if_generation, delete_entry_if_unchanged, delete_run_after_cleanup, inspect_cache,
    load_cache_entry, replace_cache_candidate, revoke_transaction, save_cache_candidate,
};
#[cfg(test)]
pub use storage::{delete_cache_entry, list_all_cache_entries, save_cache_entry};
pub use types::{Record, ReplaceCacheEntry, SaveCacheEntry};
