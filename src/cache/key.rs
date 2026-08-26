use crate::cache::digest::encode_hex;
use crate::cache::error::CacheError;
use sha2::{Digest, Sha256};

pub const MIN_CACHE_ID_LENGTH: usize = 7;

/// Compute SHA-256 hex cache key for `profile_name + "|" + canonical_repo_scope`.
pub fn compute_cache_key(profile_name: &str, canonical_repo_scope: &str) -> String {
    let input = format!("{profile_name}|{canonical_repo_scope}");
    let digest = Sha256::digest(input.as_bytes());
    encode_hex(&digest)
}

/// Compute a domain-separated SHA-256 cache key for a one-off run identifier.
pub fn compute_run_cache_key(run_id: &str) -> String {
    let mut hasher = Sha256::new();
    for part in ["ghst-cache-key-v1", "run", run_id] {
        hasher.update(part.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(part.as_bytes());
    }
    encode_hex(&hasher.finalize())
}

/// Return the shortest cache-key prefix that is unique among `cache_keys`, or
/// the full key when no distinguishing prefix exists.
///
/// Cache IDs mirror abbreviated Git object IDs: seven characters normally,
/// expanding only when another cached slot shares that prefix.
pub fn abbreviate_cache_key<'a>(cache_key: &'a str, cache_keys: &[&str]) -> &'a str {
    let mut length = MIN_CACHE_ID_LENGTH.min(cache_key.len());
    while length < cache_key.len()
        && cache_keys
            .iter()
            .any(|other| *other != cache_key && other.starts_with(&cache_key[..length]))
    {
        length += 1;
    }
    &cache_key[..length]
}

pub fn validate_cache_key(hash_key: &str) -> Result<(), CacheError> {
    if hash_key.len() == 64 && hash_key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(CacheError::InvalidKey(hash_key.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_ids_are_short_but_expand_to_remain_unique() {
        let first = "012345678aaaaaaa";
        let second = "012345678bbbbbbb";
        let distinct = "abcdef0123456789";
        let prefix = "fedcba9";
        let longer = "fedcba98";
        let keys = [first, second, distinct, prefix, longer];

        assert_eq!(abbreviate_cache_key(first, &keys), "012345678a");
        assert_eq!(abbreviate_cache_key(second, &keys), "012345678b");
        assert_eq!(abbreviate_cache_key(distinct, &keys), "abcdef0");
        assert_eq!(abbreviate_cache_key(prefix, &keys), prefix);
    }
}
