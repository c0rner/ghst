use crate::credential::{AccessToken, BaseCredential, ScopedCredential, TokenExpiry};
use crate::run::RunRecord;
use std::fmt;
use time::OffsetDateTime;

/// Non-serializable record containing feature models.
#[derive(PartialEq, Eq)]
pub enum Record {
    Base(BaseCredential),
    Scoped(ScopedCredential),
    Run(RunRecord),
}

impl Record {
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Base(_) => "base",
            Self::Scoped(_) => "scoped",
            Self::Run(_) => "run",
        }
    }

    pub fn profile(&self) -> &str {
        match self {
            Self::Base(entry) => &entry.profile,
            Self::Scoped(entry) => &entry.profile,
            Self::Run(entry) => &entry.profile,
        }
    }

    pub fn repo_scope(&self) -> &str {
        match self {
            Self::Base(_) => "all",
            Self::Scoped(entry) => &entry.repo_scope,
            Self::Run(entry) => &entry.repo_scope,
        }
    }

    pub const fn access_token(&self) -> &AccessToken {
        match self {
            Self::Base(entry) => &entry.access_token,
            Self::Scoped(entry) => &entry.access_token,
            Self::Run(entry) => &entry.access_token,
        }
    }

    pub const fn expires_at(&self) -> TokenExpiry {
        match self {
            Self::Base(entry) => entry.expires_at,
            Self::Scoped(entry) => entry.expires_at,
            Self::Run(entry) => entry.expires_at,
        }
    }

    pub fn is_safe_to_handoff_at(&self, now: OffsetDateTime) -> bool {
        self.expires_at().is_safe_to_handoff_at(now)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn compatible_with(&self, candidate: &Self, now: OffsetDateTime) -> bool {
        match (self, candidate) {
            (Self::Base(existing), Self::Base(candidate)) => {
                existing.compatible_with(candidate, now)
            }
            (Self::Scoped(existing), Self::Scoped(candidate)) => {
                existing.compatible_with(candidate, now)
            }
            _ => false,
        }
    }
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base(entry) => f.debug_tuple("Base").field(entry).finish(),
            Self::Scoped(entry) => f.debug_tuple("Scoped").field(entry).finish(),
            Self::Run(entry) => f.debug_tuple("Run").field(entry).finish(),
        }
    }
}

/// State of an inspected storage entry.
pub enum InspectionState {
    Current(Box<Record>),
    Invalid,
}

impl fmt::Debug for InspectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Current(record) => f.debug_tuple("Current").field(record).finish(),
            Self::Invalid => write!(f, "Invalid"),
        }
    }
}

/// Safe inspection snapshot of a stored record.
#[derive(Debug)]
pub struct RecordInspection {
    pub label: String,
    pub slot_id: Option<String>,
    pub state: InspectionState,
}

/// Result of conditional exact-record deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteOutcome<E = ()> {
    Deleted,
    Missing,
    Changed,
    UnlinkedSyncFailed(E),
}

/// Target specification for starting a revocation batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationSelection<'a> {
    All,
    One(&'a str),
}

pub type RevocationSnapshot = RecordInspection;

/// Result of beginning a revocation batch.
#[derive(Debug)]
pub enum RevocationBatch {
    Selected(Vec<RevocationSnapshot>),
    NotFound,
    Ambiguous,
}

/// Trait for inspecting storage entries.
pub trait InspectRecords {
    type Error: std::error::Error + 'static;

    fn inspect_records(&self) -> Result<Vec<RecordInspection>, Self::Error>;
}

/// Trait for deleting an exact inspected snapshot.
pub trait DeleteInspectedRecord {
    type Error: std::error::Error + 'static;

    fn delete_exact_record(
        &self,
        slot_id: &str,
        expected: &Record,
    ) -> Result<DeleteOutcome<Self::Error>, Self::Error>;
}

/// Trait for starting revocation under an atomic epoch advance and inspection.
pub trait BeginRevocation {
    type Error: std::error::Error + 'static;

    fn begin_revocation(
        &self,
        selection: RevocationSelection<'_>,
    ) -> Result<RevocationBatch, Self::Error>;
}
