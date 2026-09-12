pub mod store;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

pub const TOKEN_SAFETY_MARGIN: Duration = Duration::seconds(30);
pub const SCOPED_TOKEN_RENEWAL_WINDOW: Duration = Duration::minutes(10);

/// A secret access token that is zeroized on drop and never exposed by `Debug`.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccessToken(Zeroizing<String>);

impl AccessToken {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl AsRef<str> for AccessToken {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl From<String> for AccessToken {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for AccessToken {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// A parsed RFC 3339 token expiration timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TokenExpiry(OffsetDateTime);

impl TokenExpiry {
    pub const fn new(value: OffsetDateTime) -> Self {
        Self(value)
    }

    pub const fn value(self) -> OffsetDateTime {
        self.0
    }

    pub fn parse(value: &str) -> Result<Self, time::error::Parse> {
        OffsetDateTime::parse(value, &Rfc3339).map(Self)
    }

    pub fn is_safe_to_handoff_at(self, now: OffsetDateTime) -> bool {
        self.0 > now + TOKEN_SAFETY_MARGIN
    }

    pub fn is_due_for_renewal_at(self, now: OffsetDateTime) -> bool {
        self.0 <= now + SCOPED_TOKEN_RENEWAL_WINDOW
    }
}

impl fmt::Display for TokenExpiry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.0.format(&Rfc3339).map_err(|_| fmt::Error)?;
        f.write_str(&value)
    }
}

impl Serialize for TokenExpiry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for TokenExpiry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Borrowed expected provenance fields for validating a cached or existing base credential.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ExpectedBaseProvenance<'a> {
    pub profile: &'a str,
    pub authority_fingerprint: &'a str,
}

/// Discrepancy detected when checking base credential provenance.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BaseProvenanceMismatch {
    Profile,
    Authority,
}

/// A validated base credential obtained through OAuth Device Flow.
#[derive(PartialEq, Eq)]
pub struct BaseCredential {
    pub profile: String,
    pub authority_fingerprint: String,
    pub github_user: String,
    pub expires_at: TokenExpiry,
    pub access_token: AccessToken,
}

impl BaseCredential {
    pub fn generation_fingerprint(&self) -> String {
        fingerprint(&[self.access_token.as_ref()])
    }

    pub fn provenance(&self) -> ExpectedBaseProvenance<'_> {
        ExpectedBaseProvenance {
            profile: &self.profile,
            authority_fingerprint: &self.authority_fingerprint,
        }
    }

    pub fn check_provenance(
        &self,
        expected: &ExpectedBaseProvenance<'_>,
    ) -> Result<(), BaseProvenanceMismatch> {
        if self.profile != expected.profile {
            return Err(BaseProvenanceMismatch::Profile);
        }
        if self.authority_fingerprint != expected.authority_fingerprint {
            return Err(BaseProvenanceMismatch::Authority);
        }
        Ok(())
    }

    pub fn compatible_with(&self, candidate: &Self, now: OffsetDateTime) -> bool {
        if !self.expires_at.is_safe_to_handoff_at(now) {
            return false;
        }
        self.check_provenance(&candidate.provenance()).is_ok()
    }
}

impl fmt::Debug for BaseCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BaseCredential")
            .field("profile", &self.profile)
            .field("authority_fingerprint", &self.authority_fingerprint)
            .field("github_user", &self.github_user)
            .field("expires_at", &self.expires_at)
            .field("access_token", &self.access_token)
            .finish()
    }
}

/// Borrowed expected provenance fields for validating a cached or existing scoped credential.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ExpectedScopedProvenance<'a> {
    pub profile: &'a str,
    pub source_profile: &'a str,
    pub source_authority_fingerprint: &'a str,
    pub parent_generation: &'a str,
    pub policy_fingerprint: &'a str,
    pub repo_scope: &'a str,
}

/// Discrepancy detected when checking scoped credential provenance.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ScopedProvenanceMismatch {
    Profile,
    SourceProfile,
    SourceAuthority,
    RepositoryScope,
    Policy,
    ParentGeneration,
}

impl ScopedProvenanceMismatch {
    pub const fn description(self) -> &'static str {
        match self {
            Self::Profile => "profile name changed",
            Self::SourceProfile => "source profile changed",
            Self::SourceAuthority => "source GitHub App authority changed",
            Self::RepositoryScope => "repository scope changed",
            Self::Policy => "permissions or target account changed",
            Self::ParentGeneration => "parent base token generation changed",
        }
    }
}

/// A validated scoped credential minted from a base credential.
#[derive(PartialEq, Eq)]
pub struct ScopedCredential {
    pub profile: String,
    pub source_profile: String,
    pub source_authority_fingerprint: String,
    pub parent_generation: String,
    pub policy_fingerprint: String,
    pub github_user: String,
    pub repo_scope: String,
    pub expires_at: TokenExpiry,
    pub access_token: AccessToken,
}

impl ScopedCredential {
    pub fn provenance(&self) -> ExpectedScopedProvenance<'_> {
        ExpectedScopedProvenance {
            profile: &self.profile,
            source_profile: &self.source_profile,
            source_authority_fingerprint: &self.source_authority_fingerprint,
            parent_generation: &self.parent_generation,
            policy_fingerprint: &self.policy_fingerprint,
            repo_scope: &self.repo_scope,
        }
    }

    pub fn check_provenance(
        &self,
        expected: &ExpectedScopedProvenance<'_>,
    ) -> Result<(), ScopedProvenanceMismatch> {
        if self.profile != expected.profile {
            return Err(ScopedProvenanceMismatch::Profile);
        }
        if self.source_profile != expected.source_profile {
            return Err(ScopedProvenanceMismatch::SourceProfile);
        }
        if self.source_authority_fingerprint != expected.source_authority_fingerprint {
            return Err(ScopedProvenanceMismatch::SourceAuthority);
        }
        if self.repo_scope != expected.repo_scope {
            return Err(ScopedProvenanceMismatch::RepositoryScope);
        }
        if self.policy_fingerprint != expected.policy_fingerprint {
            return Err(ScopedProvenanceMismatch::Policy);
        }
        if self.parent_generation != expected.parent_generation {
            return Err(ScopedProvenanceMismatch::ParentGeneration);
        }
        Ok(())
    }

    pub fn compatible_with(&self, candidate: &Self, now: OffsetDateTime) -> bool {
        if !self.expires_at.is_safe_to_handoff_at(now) {
            return false;
        }
        self.check_provenance(&candidate.provenance()).is_ok()
    }
}

impl fmt::Debug for ScopedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedCredential")
            .field("profile", &self.profile)
            .field("source_profile", &self.source_profile)
            .field(
                "source_authority_fingerprint",
                &self.source_authority_fingerprint,
            )
            .field("parent_generation", &self.parent_generation)
            .field("policy_fingerprint", &self.policy_fingerprint)
            .field("github_user", &self.github_user)
            .field("repo_scope", &self.repo_scope)
            .field("expires_at", &self.expires_at)
            .field("access_token", &self.access_token)
            .finish()
    }
}

pub fn authority_fingerprint(client_id: &str, account: &str) -> String {
    fingerprint(&[client_id, account])
}

pub fn matches_authority_fingerprint(
    client_id: &str,
    account: &str,
    cached_fingerprint: &str,
) -> bool {
    authority_fingerprint(client_id, account) == cached_fingerprint
}

pub fn policy_fingerprint<V: fmt::Display>(
    account: &str,
    repo_scope: &str,
    permissions: &BTreeMap<String, V>,
) -> String {
    let permission_string = permissions
        .iter()
        .map(|(name, level)| format!("{name}={level}"))
        .collect::<Vec<_>>()
        .join("\n");
    fingerprint(&[account, repo_scope, &permission_string])
}

fn fingerprint(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(part.as_bytes());
    }
    encode_hex(&hasher.finalize())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_token_debug_is_redacted() {
        let token = AccessToken::new("ghu_secret_test_token".to_string());
        let debug = format!("{token:?}");
        assert_eq!(debug, "[REDACTED]");
        assert!(!debug.contains("ghu_secret_test_token"));
    }

    #[test]
    fn access_token_transparent_serialization() {
        let token = AccessToken::new("secret_abc".to_string());
        let json = serde_json::to_string(&token).unwrap();
        assert_eq!(json, "\"secret_abc\"");
        let deserialized: AccessToken = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, token);
        assert_eq!(deserialized.as_ref(), "secret_abc");
    }

    #[test]
    fn token_expiry_parse_and_display() {
        let raw = "2026-08-09T11:00:00Z";
        let expiry = TokenExpiry::parse(raw).unwrap();
        assert_eq!(expiry.to_string(), raw);
        assert_eq!(
            expiry.value(),
            OffsetDateTime::parse(raw, &Rfc3339).unwrap()
        );
    }

    #[test]
    fn token_expiry_invalid_parse() {
        assert!(TokenExpiry::parse("invalid-timestamp").is_err());
    }

    #[test]
    fn token_expiry_transparent_serialization() {
        let expiry = TokenExpiry::parse("2026-08-09T11:00:00Z").unwrap();
        let json = serde_json::to_string(&expiry).unwrap();
        assert_eq!(json, "\"2026-08-09T11:00:00Z\"");
        let deserialized: TokenExpiry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, expiry);
    }

    #[test]
    fn token_expiry_exact_handoff_and_renewal_boundaries() {
        let now = OffsetDateTime::now_utc();
        assert!(!TokenExpiry::new(now + Duration::seconds(30)).is_safe_to_handoff_at(now));
        assert!(TokenExpiry::new(now + Duration::seconds(31)).is_safe_to_handoff_at(now));
        assert!(TokenExpiry::new(now + Duration::minutes(10)).is_due_for_renewal_at(now));
        assert!(
            !TokenExpiry::new(now + Duration::minutes(10) + Duration::seconds(1))
                .is_due_for_renewal_at(now)
        );
    }

    #[test]
    fn fingerprint_outputs_match_fixed_baseline_values() {
        assert_eq!(
            authority_fingerprint("id", "acme"),
            "d91cf0a66feaf7c0e4a191af594bb810b92508c6216477985edc3c75e5d084a5"
        );

        let permissions = BTreeMap::from([("contents".to_string(), "read")]);
        assert_eq!(
            policy_fingerprint("acme", "acme/api", &permissions),
            "d0121d7469f6493208e762404c9f3b3b51edffb524c2ecf3c573b8f8f8f13715"
        );

        let base = BaseCredential {
            profile: "developer".into(),
            authority_fingerprint:
                "d91cf0a66feaf7c0e4a191af594bb810b92508c6216477985edc3c75e5d084a5".into(),
            github_user: "octocat".into(),
            expires_at: TokenExpiry::new(OffsetDateTime::now_utc() + Duration::hours(1)),
            access_token: AccessToken::from("base-token"),
        };
        assert_eq!(
            base.generation_fingerprint(),
            "57b67ea4e4041648eaee9cee6cb5971ebc0f2004c0fea34371ce7e2d29604b18"
        );
    }

    fn base_credential(now: OffsetDateTime) -> BaseCredential {
        BaseCredential {
            profile: "developer".into(),
            authority_fingerprint: "auth1".into(),
            github_user: "octocat".into(),
            expires_at: TokenExpiry::new(now + Duration::hours(1)),
            access_token: AccessToken::from("base-token"),
        }
    }

    fn scoped_credential(now: OffsetDateTime) -> ScopedCredential {
        ScopedCredential {
            profile: "reader".into(),
            source_profile: "developer".into(),
            source_authority_fingerprint: "auth1".into(),
            parent_generation: "gen1".into(),
            policy_fingerprint: "policy1".into(),
            github_user: "octocat".into(),
            repo_scope: "acme/api".into(),
            expires_at: TokenExpiry::new(now + Duration::hours(1)),
            access_token: AccessToken::from("scoped-token"),
        }
    }

    #[test]
    fn base_compatibility_uses_receiver_safety_and_provenance_only() {
        let now = OffsetDateTime::now_utc();
        let receiver = base_credential(now);
        let mut candidate = base_credential(now);
        candidate.github_user = "different-user".into();
        candidate.expires_at = TokenExpiry::new(now - Duration::hours(1));
        candidate.access_token = AccessToken::from("different-token");
        assert!(receiver.compatible_with(&candidate, now));

        candidate.authority_fingerprint = "different-authority".into();
        assert!(!receiver.compatible_with(&candidate, now));

        let mut unsafe_receiver = base_credential(now);
        unsafe_receiver.expires_at = TokenExpiry::new(now + Duration::seconds(30));
        assert!(!unsafe_receiver.compatible_with(&base_credential(now), now));
    }

    #[test]
    fn scoped_compatibility_uses_receiver_safety_and_provenance_only() {
        let now = OffsetDateTime::now_utc();
        let receiver = scoped_credential(now);
        let mut candidate = scoped_credential(now);
        candidate.github_user = "different-user".into();
        candidate.expires_at = TokenExpiry::new(now - Duration::hours(1));
        candidate.access_token = AccessToken::from("different-token");
        assert!(receiver.compatible_with(&candidate, now));

        candidate.policy_fingerprint = "different-policy".into();
        assert!(!receiver.compatible_with(&candidate, now));

        let mut unsafe_receiver = scoped_credential(now);
        unsafe_receiver.expires_at = TokenExpiry::new(now + Duration::seconds(30));
        assert!(!unsafe_receiver.compatible_with(&scoped_credential(now), now));
    }

    #[test]
    fn credentials_debug_impl_redacts_tokens() {
        let now = OffsetDateTime::now_utc();
        let base = BaseCredential {
            profile: "developer".into(),
            authority_fingerprint: "auth".into(),
            github_user: "octocat".into(),
            expires_at: TokenExpiry::new(now + Duration::hours(1)),
            access_token: AccessToken::from("base_super_secret"),
        };
        let debug = format!("{base:?}");
        assert!(!debug.contains("base_super_secret"));
        assert!(debug.contains("[REDACTED]"));

        let scoped = ScopedCredential {
            profile: "reader".into(),
            source_profile: "developer".into(),
            source_authority_fingerprint: "auth".into(),
            parent_generation: "gen".into(),
            policy_fingerprint: "policy".into(),
            github_user: "octocat".into(),
            repo_scope: "acme/api".into(),
            expires_at: TokenExpiry::new(now + Duration::hours(1)),
            access_token: AccessToken::from("scoped_super_secret"),
        };
        let debug = format!("{scoped:?}");
        assert!(!debug.contains("scoped_super_secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn base_credential_check_provenance_and_provenance_extraction() {
        let mut cred = base_credential(OffsetDateTime::now_utc());
        cred.authority_fingerprint = "auth_123".into();

        let expected = cred.provenance();
        assert_eq!(
            expected,
            ExpectedBaseProvenance {
                profile: "developer",
                authority_fingerprint: "auth_123",
            }
        );
        assert_eq!(cred.check_provenance(&expected), Ok(()));

        let wrong_profile = ExpectedBaseProvenance {
            profile: "reader",
            authority_fingerprint: "auth_123",
        };
        assert_eq!(
            cred.check_provenance(&wrong_profile),
            Err(BaseProvenanceMismatch::Profile)
        );

        let wrong_auth = ExpectedBaseProvenance {
            profile: "developer",
            authority_fingerprint: "auth_other",
        };
        assert_eq!(
            cred.check_provenance(&wrong_auth),
            Err(BaseProvenanceMismatch::Authority)
        );

        let both_wrong = ExpectedBaseProvenance {
            profile: "reader",
            authority_fingerprint: "auth_other",
        };
        assert_eq!(
            cred.check_provenance(&both_wrong),
            Err(BaseProvenanceMismatch::Profile)
        );
    }

    #[test]
    fn scoped_credential_check_provenance_and_provenance_extraction() {
        let mut cred = scoped_credential(OffsetDateTime::now_utc());
        cred.source_authority_fingerprint = "auth_123".into();
        cred.parent_generation = "gen_123".into();
        cred.policy_fingerprint = "policy_123".into();
        cred.repo_scope = "acme/repo".into();

        let expected = cred.provenance();
        assert_eq!(
            expected,
            ExpectedScopedProvenance {
                profile: "reader",
                source_profile: "developer",
                source_authority_fingerprint: "auth_123",
                parent_generation: "gen_123",
                policy_fingerprint: "policy_123",
                repo_scope: "acme/repo",
            }
        );
        assert_eq!(cred.check_provenance(&expected), Ok(()));

        let mut mismatch = expected;
        mismatch.profile = "other_profile";
        assert_eq!(
            cred.check_provenance(&mismatch),
            Err(ScopedProvenanceMismatch::Profile)
        );

        let mut mismatch = expected;
        mismatch.source_profile = "other_source";
        assert_eq!(
            cred.check_provenance(&mismatch),
            Err(ScopedProvenanceMismatch::SourceProfile)
        );

        let mut mismatch = expected;
        mismatch.source_authority_fingerprint = "other_auth";
        assert_eq!(
            cred.check_provenance(&mismatch),
            Err(ScopedProvenanceMismatch::SourceAuthority)
        );

        let mut mismatch = expected;
        mismatch.repo_scope = "other_repo";
        assert_eq!(
            cred.check_provenance(&mismatch),
            Err(ScopedProvenanceMismatch::RepositoryScope)
        );

        let mut mismatch = expected;
        mismatch.policy_fingerprint = "other_policy";
        assert_eq!(
            cred.check_provenance(&mismatch),
            Err(ScopedProvenanceMismatch::Policy)
        );

        let mut mismatch = expected;
        mismatch.parent_generation = "other_gen";
        assert_eq!(
            cred.check_provenance(&mismatch),
            Err(ScopedProvenanceMismatch::ParentGeneration)
        );

        let mut multi_mismatch = expected;
        multi_mismatch.profile = "other_profile";
        multi_mismatch.source_profile = "other_source";
        assert_eq!(
            cred.check_provenance(&multi_mismatch),
            Err(ScopedProvenanceMismatch::Profile)
        );

        let mut multi_mismatch2 = expected;
        multi_mismatch2.repo_scope = "other_repo";
        multi_mismatch2.policy_fingerprint = "other_policy";
        multi_mismatch2.parent_generation = "other_gen";
        assert_eq!(
            cred.check_provenance(&multi_mismatch2),
            Err(ScopedProvenanceMismatch::RepositoryScope)
        );
    }
}
