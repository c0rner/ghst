use crate::cache::{RootCacheEntry, TokenExpiry};
use crate::config::Config;
use std::fmt;
use std::path::Path;
use time::OffsetDateTime;

pub struct AcquiredToken {
    pub access_token: crate::cache::AccessToken,
    pub expires_at: TokenExpiry,
    pub profile: String,
    pub repo_scope: String,
}

impl fmt::Debug for AcquiredToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcquiredToken")
            .field("access_token", &self.access_token)
            .field("expires_at", &self.expires_at)
            .field("profile", &self.profile)
            .field("repo_scope", &self.repo_scope)
            .finish()
    }
}

pub enum RootPersistence {
    Saved(RootCacheEntry),
    Retained(RootCacheEntry),
}

pub struct AcquireRequest<'a> {
    pub config: &'a Config,
    pub cache_dir: &'a Path,
    pub profile_name: &'a str,
    pub repositories: &'a [String],
    pub now: OffsetDateTime,
}
