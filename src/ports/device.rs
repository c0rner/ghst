use super::base::IssuedBaseToken;
use super::remote::RemoteError;
use std::{fmt, time::Duration};
use zeroize::Zeroizing;

pub trait DeviceFlowClient {
    fn request_device_code(&self, client_id: &str) -> Result<DeviceAuthorization, RemoteError>;

    fn poll_access_token(
        &self,
        client_id: &str,
        device_code: &str,
    ) -> Result<DeviceFlowPoll, RemoteError>;
}

pub struct DeviceAuthorization {
    pub device_code: Zeroizing<String>,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: Duration,
    pub interval: Duration,
}

impl fmt::Debug for DeviceAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceAuthorization")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

#[derive(Debug)]
pub enum DeviceFlowPoll {
    Pending,
    SlowDown,
    Authorized(IssuedBaseToken),
    Expired,
    AccessDenied,
}
