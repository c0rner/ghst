use crate::cache::digest::encode_hex;
use crate::cache::error::CacheError;
use sha2::{Digest, Sha256};

/// Compute SHA-256 hex cache key for `profile_name + "|" + canonical_repo_scope`.
pub fn compute_cache_key(profile_name: &str, canonical_repo_scope: &str) -> String {
    let input = format!("{profile_name}|{canonical_repo_scope}");
    let digest = Sha256::digest(input.as_bytes());
    encode_hex(&digest)
}

pub fn validate_cache_key(hash_key: &str) -> Result<(), CacheError> {
    if hash_key.len() == 64 && hash_key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(CacheError::InvalidKey(hash_key.to_string()))
    }
}
