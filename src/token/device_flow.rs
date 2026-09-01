use crate::token::{
    DeviceAuthorization, DeviceFlowClient, DeviceFlowPoll, IssuedBaseToken, RemoteError,
};
use std::fmt;
use std::time::Duration;
use tracing::{debug, warn};

#[derive(Debug)]
pub enum DeviceFlowError {
    Remote(RemoteError),
    Expired,
    AccessDenied,
}

impl fmt::Display for DeviceFlowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Remote(source) => source.fmt(formatter),
            Self::Expired => write!(formatter, "device code expired"),
            Self::AccessDenied => write!(formatter, "authorization request was denied"),
        }
    }
}

impl std::error::Error for DeviceFlowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Remote(source) => Some(source),
            Self::Expired | Self::AccessDenied => None,
        }
    }
}

impl From<RemoteError> for DeviceFlowError {
    fn from(source: RemoteError) -> Self {
        Self::Remote(source)
    }
}

pub struct DeviceFlow<'a, C, S> {
    client: &'a C,
    sleep: S,
    profile_name: &'a str,
}

impl<'a, C, S> DeviceFlow<'a, C, S>
where
    C: DeviceFlowClient,
    S: FnMut(Duration),
{
    pub const fn new(client: &'a C, sleep: S, profile_name: &'a str) -> Self {
        Self {
            client,
            sleep,
            profile_name,
        }
    }

    pub fn request_authorization(
        &self,
        client_id: &str,
    ) -> Result<DeviceAuthorization, DeviceFlowError> {
        self.client
            .request_device_code(client_id)
            .map_err(Into::into)
    }

    pub fn poll_authorization(
        &mut self,
        client_id: &str,
        authorization: &DeviceAuthorization,
    ) -> Result<IssuedBaseToken, DeviceFlowError> {
        let mut interval = authorization.interval;
        loop {
            (self.sleep)(interval);
            let poll = match self
                .client
                .poll_access_token(client_id, authorization.device_code.as_str())
            {
                Ok(poll) => poll,
                Err(source) => {
                    debug!(profile = self.profile_name, error = %source, "device authorization failed");
                    return Err(DeviceFlowError::Remote(source));
                }
            };
            match poll {
                DeviceFlowPoll::Authorized(token) => return Ok(token),
                DeviceFlowPoll::Pending => {
                    tracing::trace!(
                        profile = self.profile_name,
                        "device authorization is still pending"
                    );
                }
                DeviceFlowPoll::SlowDown => {
                    interval += Duration::from_secs(5);
                    warn!(
                        profile = self.profile_name,
                        poll_interval_seconds = interval.as_secs(),
                        "GitHub requested slower device authorization polling"
                    );
                }
                DeviceFlowPoll::Expired => {
                    debug!(profile = self.profile_name, "device authorization expired");
                    return Err(DeviceFlowError::Expired);
                }
                DeviceFlowPoll::AccessDenied => {
                    debug!(
                        profile = self.profile_name,
                        "device authorization was denied"
                    );
                    return Err(DeviceFlowError::AccessDenied);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::AccessToken;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use zeroize::Zeroizing;

    struct MockClient {
        polls: RefCell<VecDeque<Result<DeviceFlowPoll, RemoteError>>>,
        poll_calls: Cell<usize>,
    }

    impl DeviceFlowClient for MockClient {
        fn request_device_code(
            &self,
            _client_id: &str,
        ) -> Result<DeviceAuthorization, RemoteError> {
            Ok(authorization())
        }

        fn poll_access_token(
            &self,
            _client_id: &str,
            _device_code: &str,
        ) -> Result<DeviceFlowPoll, RemoteError> {
            self.poll_calls.set(self.poll_calls.get() + 1);
            self.polls.borrow_mut().pop_front().unwrap()
        }
    }

    fn client(polls: Vec<Result<DeviceFlowPoll, RemoteError>>) -> MockClient {
        MockClient {
            polls: RefCell::new(VecDeque::from(polls)),
            poll_calls: Cell::new(0),
        }
    }

    fn authorization() -> DeviceAuthorization {
        DeviceAuthorization {
            device_code: Zeroizing::new("device-secret".into()),
            user_code: "ABCD-EFGH".into(),
            verification_uri: "https://github.com/login/device".into(),
            expires_in: Duration::from_mins(15),
            interval: Duration::from_secs(5),
        }
    }

    fn issued() -> IssuedBaseToken {
        IssuedBaseToken {
            access_token: AccessToken::new("issued-secret".into()),
            expires_in: Some(28_800),
        }
    }

    #[test]
    fn pending_retains_interval_and_slow_down_increases_subsequent_delays() {
        let client = client(vec![
            Ok(DeviceFlowPoll::Pending),
            Ok(DeviceFlowPoll::SlowDown),
            Ok(DeviceFlowPoll::Pending),
            Ok(DeviceFlowPoll::Authorized(issued())),
        ]);
        let mut delays = Vec::new();
        let mut flow = DeviceFlow::new(&client, |delay| delays.push(delay), "developer");

        let token = flow
            .poll_authorization("client-id", &authorization())
            .unwrap();

        assert_eq!(token.access_token.as_ref(), "issued-secret");
        assert_eq!(
            delays,
            vec![
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(10),
                Duration::from_secs(10),
            ]
        );
        assert_eq!(client.poll_calls.get(), 4);
    }

    #[test]
    fn expiry_and_denial_stop_without_extra_polling() {
        for (poll, expected_expired) in [
            (DeviceFlowPoll::Expired, true),
            (DeviceFlowPoll::AccessDenied, false),
        ] {
            let client = client(vec![Ok(poll), Ok(DeviceFlowPoll::Authorized(issued()))]);
            let mut delays = Vec::new();
            let mut flow = DeviceFlow::new(&client, |delay| delays.push(delay), "developer");

            let error = flow
                .poll_authorization("client-id", &authorization())
                .unwrap_err();

            assert_eq!(matches!(error, DeviceFlowError::Expired), expected_expired);
            assert_eq!(client.poll_calls.get(), 1);
            assert_eq!(delays, vec![Duration::from_secs(5)]);
        }
    }

    #[test]
    fn remote_failure_stops_without_extra_polling() {
        let client = client(vec![
            Err(RemoteError::Transport(std::io::Error::other("offline"))),
            Ok(DeviceFlowPoll::Authorized(issued())),
        ]);
        let mut delays = Vec::new();
        let mut flow = DeviceFlow::new(&client, |delay| delays.push(delay), "developer");

        let error = flow
            .poll_authorization("client-id", &authorization())
            .unwrap_err();

        assert!(matches!(
            error,
            DeviceFlowError::Remote(RemoteError::Transport(_))
        ));
        assert_eq!(client.poll_calls.get(), 1);
        assert_eq!(delays, vec![Duration::from_secs(5)]);
    }

    #[test]
    fn secret_bearing_port_types_have_redacted_debug_output() {
        let output = format!("{:?}", authorization());
        assert!(!output.contains("device-secret"));
        assert!(output.contains("[REDACTED]"));

        let output = format!("{:?}", DeviceFlowPoll::Authorized(issued()));
        assert!(!output.contains("issued-secret"));
        assert!(output.contains("[REDACTED]"));
    }
}
