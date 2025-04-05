use protocol::errors::X3DHError;
use std::env;
use std::fmt::Display;
use anyhow::Error;

#[derive(Debug)]
pub(crate) enum ServerError {
    X3DHError(X3DHError),
    VarError(env::VarError),
    UserNotFoundError,
    UserAlreadyExists,
    InvalidPreKeyBundle,
    InvalidRequest,
    Base64DecodeError(base64::DecodeError),
    GenericError(Error),
}

impl Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            ServerError::X3DHError(e) => write!(f, "X3DH error: {}", e),
            ServerError::VarError(e) => write!(f, "Environment variable error: {}", e),
            ServerError::UserNotFoundError => write!(f, "User not found"),
            ServerError::UserAlreadyExists => write!(f, "User already exists"),
            ServerError::InvalidPreKeyBundle => write!(f, "Invalid prekey bundle"),
            ServerError::InvalidRequest => write!(f, "Invalid request"),
            ServerError::Base64DecodeError(decode_error) => write!(f, "Error: {}", decode_error),
            ServerError::GenericError(e) => write!(f, "Generic error: {}", e),
        }
    }
}
impl From<Error> for ServerError {
    fn from(value: Error) -> Self {
        ServerError::GenericError(value)
    }
}

impl std::error::Error for ServerError {}

impl From<X3DHError> for ServerError {
    fn from(value: X3DHError) -> Self {
        ServerError::X3DHError(value)
    }
}

impl From<env::VarError> for ServerError {
    fn from(value: env::VarError) -> Self {
        ServerError::VarError(value)
    }
}

impl From<base64::DecodeError> for ServerError {
    fn from(value: base64::DecodeError) -> Self {
        ServerError::Base64DecodeError(value)
    }
}
