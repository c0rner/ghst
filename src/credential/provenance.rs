/// The policy and source evidence required for reusing a scoped credential.
#[derive(Clone, Copy, Debug)]
pub struct ScopedProvenance<'a> {
    pub profile: &'a str,
    pub source_profile: &'a str,
    pub source_authority: &'a str,
    pub repo_scope: &'a str,
    pub policy: &'a str,
    pub parent_generation: &'a str,
}

impl ScopedProvenance<'_> {
    pub fn mismatch(&self, expected: &Self) -> Option<&'static str> {
        if self.profile != expected.profile {
            Some("profile changed")
        } else if self.source_profile != expected.source_profile {
            Some("source profile changed")
        } else if self.source_authority != expected.source_authority {
            Some("source GitHub App authority changed")
        } else if self.repo_scope != expected.repo_scope {
            Some("repository scope changed")
        } else if self.policy != expected.policy {
            Some("permissions or target account changed")
        } else if self.parent_generation != expected.parent_generation {
            Some("parent base token generation changed")
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_reuse_requires_every_provenance_boundary_to_match() {
        let expected = ScopedProvenance {
            profile: "reader",
            source_profile: "developer",
            source_authority: "authority",
            repo_scope: "acme/api",
            policy: "policy",
            parent_generation: "generation",
        };
        assert!(expected.mismatch(&expected).is_none());
        for changed in [
            ScopedProvenance {
                profile: "other",
                ..expected
            },
            ScopedProvenance {
                source_profile: "other",
                ..expected
            },
            ScopedProvenance {
                source_authority: "other",
                ..expected
            },
            ScopedProvenance {
                repo_scope: "all",
                ..expected
            },
            ScopedProvenance {
                policy: "other",
                ..expected
            },
            ScopedProvenance {
                parent_generation: "other",
                ..expected
            },
        ] {
            assert!(changed.mismatch(&expected).is_some());
            assert!(expected.mismatch(&changed).is_some());
        }
    }
}
