mod error;
use super::stored::StoredCredential;
pub use error::StoreError;
use time::OffsetDateTime;

/// Conditions captured before remote issuance, checked together under the store lock.
#[derive(Clone, Copy)]
pub struct IssuanceGuard<'a> {
    pub epoch: u64,
    pub source: ExpectedSource<'a>,
}
#[derive(Clone, Copy)]
pub struct ExpectedSource<'a> {
    pub key: &'a str,
    pub generation: &'a str,
}

pub enum InspectionState {
    Current(Box<StoredCredential>),
    Invalid,
}
pub struct Inspection {
    pub label: String,
    pub cache_key: Option<String>,
    pub state: InspectionState,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteBaseOutcome {
    Deleted,
    Missing,
    Changed,
}

/// Reads current validated values; malformed or insecure artifacts never become cache misses.
pub trait Inspect {
    fn load(&self, key: &str) -> Result<Option<StoredCredential>, StoreError>;
    fn inspect(&self) -> Result<Vec<Inspection>, StoreError>;
}
/// Commits only under the unchanged epoch and source generation.
/// A compatible concurrent winner is retained; renewal otherwise replaces only the exact
/// selected child. Persistence is durable before a displaced credential is returned for cleanup.
pub trait Issue {
    fn epoch(&self) -> Result<u64, StoreError>;
    fn commit(
        &self,
        key: &str,
        candidate: &StoredCredential,
        guard: IssuanceGuard<'_>,
    ) -> Result<SaveStoredCredential, StoreError>;
    fn renew(
        &self,
        key: &str,
        expected: &StoredCredential,
        candidate: &StoredCredential,
        guard: IssuanceGuard<'_>,
        now: OffsetDateTime,
    ) -> Result<ReplaceStoredCredential, StoreError>;
}
/// Removes only the selected generation or exact inspected value under the store lock.
pub trait Remove {
    fn delete_unchanged(&self, key: &str, expected: &StoredCredential) -> Result<bool, StoreError>;
    fn delete_base_generation(
        &self,
        key: &str,
        generation: &str,
    ) -> Result<DeleteBaseOutcome, StoreError>;
}

/// Revocation policy sees inspected values, never a transaction or filesystem handle.
/// The store owns selection, epoch invalidation, deletion and durability ordering.
pub trait Revocation {
    fn should_delete(&mut self, entry: &Inspection) -> bool;
    fn deleted(&mut self, label: &str, result: Result<bool, StoreError>);
}
pub trait Revoke {
    fn revoke<R: Revocation>(
        &self,
        selected_id: Option<&str>,
        policy: &mut R,
    ) -> Result<usize, StoreError>;
}

/// Persists a base candidate under the captured epoch, retaining a valid same-authority winner.
pub trait Login {
    fn commit_login(
        &self,
        key: &str,
        candidate: &super::stored::StoredBase,
        epoch: u64,
    ) -> Result<SaveStoredCredential, StoreError>;
}

/// Result of attempting to persist an immutable cache entry.
pub enum SaveStoredCredential {
    Saved,
    Retained(Box<StoredCredential>),
}

/// Result of atomically replacing the exact scoped entry selected for renewal.
pub enum ReplaceStoredCredential {
    Replaced(Box<StoredCredential>),
    Retained(Box<StoredCredential>),
}

impl std::fmt::Debug for SaveStoredCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Saved => f.write_str("Saved"),
            Self::Retained(entry) => f.debug_tuple("Retained").field(entry).finish(),
        }
    }
}
impl std::fmt::Debug for ReplaceStoredCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Replaced(entry) => f.debug_tuple("Replaced").field(entry).finish(),
            Self::Retained(entry) => f.debug_tuple("Retained").field(entry).finish(),
        }
    }
}
