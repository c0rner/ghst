use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
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
    fn access_token_as_ref_and_conversions() {
        let token = AccessToken::from("my_token");
        assert_eq!(token.as_ref(), "my_token");
        let token2 = AccessToken::from("my_token".to_string());
        assert_eq!(token2.as_ref(), "my_token");
        assert_eq!(token, token2);
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
}
