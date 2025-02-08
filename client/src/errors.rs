use std::fmt::{Display, Formatter};
use std::string::FromUtf8Error;
use tokio_tungstenite::tungstenite::Error as WsError;
use protocol::errors::X3DHError;

#[derive(Debug)]
pub enum ClientError {
    ConnectionError(WsError),
    ProtocolError(X3DHError),
    ServerResponseError,
    UserAlreadyExistsError,
    UserNotFoundError,
    SerializationError,
    GenericError(String),
    SendError,
}

impl Display for ClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            ClientError::ConnectionError(e) => write!(f, "Connection error: {}", e),
            ClientError::ProtocolError(e) => write!(f, "Protocol error: {}", e),
            ClientError::ServerResponseError => write!(f, "Server response error"),
            ClientError::UserAlreadyExistsError => write!(f, "User already exists"),
            ClientError::UserNotFoundError => write!(f, "User not found"),
            ClientError::SerializationError => write!(f, "Serialization error"),
            ClientError::SendError => write!(f, "Failed to send message"),
            ClientError::GenericError(e) => write!(f, "Error: {}", e),

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

impl From<base64::DecodeError> for ClientError {
    fn from(_: base64::DecodeError) -> Self {
        ClientError::GenericError("Failed to decode base64".to_string())
    }
}

impl From<FromUtf8Error> for ClientError {
    fn from(_: FromUtf8Error) -> Self {
        ClientError::GenericError("Failed to decode utf8".to_string())
    }
}

