use std::env;
use std::fmt::Display;
use protocol::errors::X3DHError;

#[derive(Debug)]
pub(crate) enum ServerError {
    X3DHError(X3DHError),
    VarError(env::VarError),
    UserNotFoundError
}

impl Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            ServerError::X3DHError(e) => write!(f, "X3DH error: {}", e),
            ServerError::VarError(e) => write!(f, "Environment variable error: {}", e),
            ServerError::UserNotFoundError => write!(f, "User not found")
        }
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