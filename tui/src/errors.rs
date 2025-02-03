use std::fmt::{Display, Formatter};
use client::errors::ClientError;

pub(crate) enum TuiError {
    EmptyUsernameInput,
    ClientError(client::errors::ClientError),
}

impl Display for TuiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TuiError::EmptyUsernameInput => write!(f, "Username cannot be empty"),
            TuiError::ClientError(e) => write!(f, "Client error: {}", e),
        }
    }
}

impl From<ClientError> for TuiError {
    fn from(value: ClientError) -> Self {
        TuiError::ClientError(value)
    }
}