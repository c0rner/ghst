mod error;
mod fs;
mod key;
mod storage;
mod types;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub use error::CacheError;
pub use fs::cache_epoch;
#[allow(unused_imports)]
pub use fs::ensure_cache_dir;
pub use key::compute_cache_key;
#[cfg(test)]
pub use storage::list_all_cache_entries;
#[allow(unused_imports)]
pub use storage::{
    CacheInspection, CacheInspectionState, ClearTransaction, clear_transaction, delete_cache_entry,
    inspect_cache, load_cache_entry, save_cache_candidate, save_cache_entry,
};
pub use types::{
    AccessToken, CACHE_SCHEMA_VERSION, CacheEntry, DerivedCacheEntry, RootCacheEntry,
    SaveCacheEntry, TokenExpiry, authority_fingerprint, format_rfc3339, policy_fingerprint,
};
