use std::fmt::{Display, Formatter};
use tokio_tungstenite::tungstenite::Error as WsError;
use protocol::errors::X3DHError;

#[derive(Debug)]
pub enum ClientError {
    ConnectionError(WsError),
    ProtocolError(X3DHError),
    ServerResponseError,
    UserAlreadyExistsError,
    UserNotFoundError,
}

impl Display for ClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            ClientError::ConnectionError(e) => write!(f, "Connection error: {}", e),
            ClientError::ProtocolError(e) => write!(f, "Protocol error: {}", e),
            ClientError::ServerResponseError => write!(f, "Server response error"),
            ClientError::UserAlreadyExistsError => write!(f, "User already exists"),
            ClientError::UserNotFoundError => write!(f, "User not found"),
        }
    }
}

impl From<WsError> for ClientError {
    fn from(value: WsError) -> Self {
        ClientError::ConnectionError(value)
    }
}

impl From<X3DHError> for ClientError {
    fn from(value: X3DHError) -> Self {
        ClientError::ProtocolError(value)
    }
}

impl From<()> for ClientError {
    fn from(_: ()) -> Self {
        ClientError::ServerResponseError
    }
}