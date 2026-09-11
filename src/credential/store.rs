use crate::credential::{BaseCredential, ScopedCredential};
use time::OffsetDateTime;

/// Logical guard representing a captured storage epoch without holding a lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuanceGuard(pub(crate) u64);

impl IssuanceGuard {
    #[inline]
    pub const fn new(epoch: u64) -> Self {
        Self(epoch)
    }

    #[inline]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Identifies the expected parent base credential generation during scoped/run issuance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceGuard<'a> {
    pub source_profile: &'a str,
    pub expected_generation: &'a str,
}

impl<'a> SourceGuard<'a> {
    pub const fn new(source_profile: &'a str, expected_generation: &'a str) -> Self {
        Self {
            source_profile,
            expected_generation,
        }
    }
}

/// Outcome of persisting a candidate base credential.
#[derive(Debug, PartialEq, Eq)]
pub enum CommitBaseOutcome {
    Saved,
    Retained(BaseCredential),
    EpochChanged,
}

/// Outcome of persisting a candidate scoped credential.
#[derive(Debug, PartialEq, Eq)]
pub enum CommitScopedOutcome {
    Saved,
    Retained(Box<ScopedCredential>),
    EpochChanged,
    BaseGenerationChanged,
}

/// Outcome of replacing a renewable credential.
#[derive(Debug, PartialEq, Eq)]
pub enum ReplaceOutcome<T> {
    Replaced(T),
    Retained(T),
    EpochChanged,
    BaseGenerationChanged,
    RenewalEntryChanged,
}

/// Outcome of deleting a base credential if its generation matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteBaseOutcome {
    Deleted,
    Missing,
    Changed,
}

/// Trait for reading reusable credentials by logical profile and scope.
pub trait ReadCredentials {
    type Error: std::error::Error + 'static;

    fn read_base(&self, profile: &str) -> Result<Option<BaseCredential>, Self::Error>;
    fn read_scoped(
        &self,
        profile: &str,
        repo_scope: &str,
    ) -> Result<Option<ScopedCredential>, Self::Error>;
}

/// Trait for capturing an issuance guard before network operations.
pub trait IssuanceGuardStore {
    type Error: std::error::Error + 'static;

    fn issuance_guard(&self) -> Result<IssuanceGuard, Self::Error>;
}

/// Trait for committing reusable credentials and conditional base deletion.
pub trait WriteCredentials {
    type Error: std::error::Error + 'static;

    fn commit_base(
        &self,
        candidate: &BaseCredential,
        guard: IssuanceGuard,
    ) -> Result<CommitBaseOutcome, Self::Error>;

    fn commit_scoped(
        &self,
        candidate: &ScopedCredential,
        guard: IssuanceGuard,
        source_guard: &SourceGuard<'_>,
    ) -> Result<CommitScopedOutcome, Self::Error>;

    fn renew_scoped(
        &self,
        expected: &ScopedCredential,
        candidate: &ScopedCredential,
        guard: IssuanceGuard,
        source_guard: &SourceGuard<'_>,
        now: OffsetDateTime,
    ) -> Result<ReplaceOutcome<ScopedCredential>, Self::Error>;

    fn delete_base_if_generation(
        &self,
        profile: &str,
        expected_generation: &str,
    ) -> Result<DeleteBaseOutcome, Self::Error>;
}
