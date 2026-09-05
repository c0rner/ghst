use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunPhase {
    Pending,
    Running { child_pid: u32 },
    CleanupPending { child_pid: Option<u32> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunOwner<'a> {
    pub run_id: &'a str,
    pub wrapper_pid: u32,
}

/// Validated lifecycle state; a running lease always identifies its child.
pub struct RunLifecycle<'a> {
    owner: RunOwner<'a>,
    phase: RunPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunLifecycleError {
    InvalidChild,
    PendingOwnership,
    RunningOwnership,
    AlreadyClaimed,
}

impl fmt::Display for RunLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidChild => "run state and child PID are inconsistent",
            Self::PendingOwnership => "pending run ownership did not match",
            Self::RunningOwnership => "released run ownership did not match",
            Self::AlreadyClaimed => "run was already claimed for cleanup",
        })
    }
}

impl std::error::Error for RunLifecycleError {}

impl<'a> RunLifecycle<'a> {
    pub const fn new(owner: RunOwner<'a>, phase: RunPhase) -> Self {
        Self { owner, phase }
    }

    pub fn activate(
        self,
        owner: RunOwner<'_>,
        child_pid: u32,
    ) -> Result<RunPhase, RunLifecycleError> {
        self.require_pending(owner)?;
        Ok(RunPhase::Running { child_pid })
    }

    pub fn abort(
        self,
        owner: RunOwner<'_>,
        child_pid: Option<u32>,
    ) -> Result<RunPhase, RunLifecycleError> {
        self.require_pending(owner)?;
        Ok(RunPhase::CleanupPending { child_pid })
    }

    pub fn finish(
        self,
        owner: RunOwner<'_>,
        child_pid: u32,
    ) -> Result<RunPhase, RunLifecycleError> {
        if self.owner != owner || self.phase != (RunPhase::Running { child_pid }) {
            return Err(RunLifecycleError::RunningOwnership);
        }
        Ok(RunPhase::CleanupPending {
            child_pid: Some(child_pid),
        })
    }

    pub const fn claim_abandoned(self) -> Result<RunPhase, RunLifecycleError> {
        match self.phase {
            RunPhase::Pending => Ok(RunPhase::CleanupPending { child_pid: None }),
            RunPhase::Running { child_pid } => Ok(RunPhase::CleanupPending {
                child_pid: Some(child_pid),
            }),
            RunPhase::CleanupPending { .. } => Err(RunLifecycleError::AlreadyClaimed),
        }
    }

    fn require_pending(&self, owner: RunOwner<'_>) -> Result<(), RunLifecycleError> {
        if self.owner != owner || self.phase != RunPhase::Pending {
            return Err(RunLifecycleError::PendingOwnership);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_reject_stale_owners_and_phases() {
        let owner = RunOwner {
            run_id: "run",
            wrapper_pid: 100,
        };
        for stale in [
            RunOwner {
                run_id: "other",
                ..owner
            },
            RunOwner {
                wrapper_pid: 101,
                ..owner
            },
        ] {
            assert_eq!(
                RunLifecycle::new(owner, RunPhase::Pending).activate(stale, 200),
                Err(RunLifecycleError::PendingOwnership)
            );
            assert_eq!(
                RunLifecycle::new(owner, RunPhase::Pending).abort(stale, None),
                Err(RunLifecycleError::PendingOwnership)
            );
            assert_eq!(
                RunLifecycle::new(owner, RunPhase::Running { child_pid: 200 }).finish(stale, 200),
                Err(RunLifecycleError::RunningOwnership)
            );
        }
        for phase in [
            RunPhase::Running { child_pid: 200 },
            RunPhase::CleanupPending { child_pid: None },
        ] {
            assert_eq!(
                RunLifecycle::new(owner, phase).activate(owner, 200),
                Err(RunLifecycleError::PendingOwnership)
            );
            assert_eq!(
                RunLifecycle::new(owner, phase).abort(owner, Some(200)),
                Err(RunLifecycleError::PendingOwnership)
            );
        }
        for phase in [
            RunPhase::Pending,
            RunPhase::Running { child_pid: 201 },
            RunPhase::CleanupPending {
                child_pid: Some(200),
            },
        ] {
            assert_eq!(
                RunLifecycle::new(owner, phase).finish(owner, 200),
                Err(RunLifecycleError::RunningOwnership)
            );
        }
        assert_eq!(
            RunLifecycle::new(owner, RunPhase::CleanupPending { child_pid: None })
                .claim_abandoned(),
            Err(RunLifecycleError::AlreadyClaimed)
        );
    }
}
