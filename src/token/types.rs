use std::fmt;
use std::path::Path;

use crate::domain::credential::{AccessToken, TokenExpiry};
use crate::domain::profile::ResolvedTokenProfile;

pub struct AcquiredToken {
    pub access_token: AccessToken,
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

pub enum BasePersistence {
    Saved(BaseTokenStatus),
    Retained(BaseTokenStatus),
}

pub struct BaseTokenStatus {
    pub github_user: String,
    pub expires_at: TokenExpiry,
}

pub struct AcquireRequest<'a> {
    pub profile: &'a ResolvedTokenProfile<'a>,
    pub cache_dir: &'a Path,
    pub repositories: &'a [String],
}
