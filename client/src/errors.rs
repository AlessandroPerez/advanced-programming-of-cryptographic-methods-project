use tokio_tungstenite::tungstenite::Error as WsError;
use protocol::errors::X3DHError;

#[derive(Debug)]
pub enum ClientError {
    ConnectionError(WsError),
    ProtocolError(X3DHError),
    ServerResponseError,
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