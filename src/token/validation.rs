use super::TokenError;
use crate::cache::TokenExpiry;
use time::{Duration, OffsetDateTime};

pub(super) const MAX_ROOT_LIFETIME_SECONDS: u64 = 8 * 60 * 60;
pub(super) const MAX_SCOPED_LIFETIME: Duration = Duration::hours(8);
pub(super) const SCOPED_EXPIRY_ROUNDING_TOLERANCE: Duration = Duration::seconds(1);

pub fn validate_root_expiry(
    expires_in: Option<u64>,
    now: OffsetDateTime,
) -> Result<TokenExpiry, TokenError> {
    let seconds = expires_in.ok_or_else(|| TokenError::InvalidLifetime {
        token_kind: "root",
        reason: "response did not contain expires_in".into(),
    })?;
    if seconds == 0 || seconds > MAX_ROOT_LIFETIME_SECONDS {
        let reason = if seconds == 0 {
            "expires_in must be positive".into()
        } else {
            format!("expires_in of {seconds} seconds exceeds the supported eight-hour maximum")
        };
        return Err(TokenError::InvalidLifetime {
            token_kind: "root",
            reason,
        });
    }
    let seconds = i64::try_from(seconds).map_err(|_| TokenError::InvalidLifetime {
        token_kind: "root",
        reason: "expires_in cannot be represented safely".into(),
    })?;
    let expiry = TokenExpiry::new(now + Duration::seconds(seconds));
    if !expiry.is_usable_at(now) {
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
    if !expiry.is_usable_at(now) {
        return Err(TokenError::InvalidLifetime {
            token_kind: "scoped",
            reason: "expires_at is not beyond the 30-second safety margin".into(),
        });
    }
    if expiry.value() > now + MAX_SCOPED_LIFETIME + SCOPED_EXPIRY_ROUNDING_TOLERANCE {
        return Err(TokenError::InvalidLifetime {
            token_kind: "scoped",
            reason: "expires_at exceeds the supported eight-hour maximum and one-second timestamp rounding tolerance".into(),
        });
    }
    Ok(expiry)
}
