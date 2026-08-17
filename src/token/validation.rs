use super::TokenError;
use crate::cache::TokenExpiry;
use time::{Duration, OffsetDateTime};

pub fn validate_root_expiry(
    expires_in: Option<u64>,
    now: OffsetDateTime,
) -> Result<TokenExpiry, TokenError> {
    let seconds = expires_in.ok_or_else(|| TokenError::InvalidLifetime {
        token_kind: "root",
        reason: "response did not contain expires_in".into(),
    })?;
    let seconds = i64::try_from(seconds).map_err(|_| TokenError::InvalidLifetime {
        token_kind: "root",
        reason: "expires_in cannot be represented safely".into(),
    })?;
    let expiry = now
        .checked_add(Duration::seconds(seconds))
        .map(TokenExpiry::new)
        .ok_or_else(|| TokenError::InvalidLifetime {
            token_kind: "root",
            reason: "expires_in cannot be represented safely".into(),
        })?;
    if !expiry.is_safe_to_handoff_at(now) {
        return Err(TokenError::InvalidLifetime {
            token_kind: "root",
            reason: "expires_in is not beyond the 30-second safety margin".into(),
        });
    }
    Ok(expiry)
}

pub fn validate_scoped_expiry(
    value: Option<&str>,
    now: OffsetDateTime,
) -> Result<TokenExpiry, TokenError> {
    let value = value.ok_or_else(|| TokenError::InvalidLifetime {
        token_kind: "scoped",
        reason: "response did not contain expires_at".into(),
    })?;
    let expiry = TokenExpiry::parse(value).map_err(|_| TokenError::InvalidLifetime {
        token_kind: "scoped",
        reason: "expires_at is not valid RFC 3339".into(),
    })?;
    if !expiry.is_safe_to_handoff_at(now) {
        return Err(TokenError::InvalidLifetime {
            token_kind: "scoped",
            reason: "expires_at is not beyond the 30-second safety margin".into(),
        });
    }
    Ok(expiry)
}
