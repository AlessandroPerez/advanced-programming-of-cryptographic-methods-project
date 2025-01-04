use std::fmt::{Display, Formatter};
use aes::cipher::crypto_common;

#[derive(Debug)]
pub enum X3DHError {
    InvalidSignature(ed25519_dalek::SignatureError),
    HkdfInvalidLengthError(hkdf::InvalidLength),
    AesGcmInvalidLength(crypto_common::InvalidLength),
    AesGcmError(aes_gcm::Error),
    Base64DecodeError(base64::DecodeError),
    InvalidPreKeyBundle,
}

impl Display for X3DHError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            X3DHError::InvalidSignature(e) => write!(f, "Invalid signature: {}", e),
            X3DHError::HkdfInvalidLengthError(e) => write!(f, "Invalid length: {}", e),
            X3DHError::AesGcmError(e) => write!(f, "AES GCM error: {}", e),
            X3DHError::AesGcmInvalidLength(e) => write!(f, "Invalid length: {}", e),
            X3DHError::Base64DecodeError(e) => write!(f, "Base64 decode error: {}", e),
            X3DHError::InvalidPreKeyBundle => write!(f, "Invalid prekey bundle"),
        }
    }
}

impl std::error::Error for X3DHError {}

impl From<hkdf::InvalidLength> for X3DHError {
    fn from(value: hkdf::InvalidLength) -> Self {
        X3DHError::HkdfInvalidLengthError(value)
    }
}

impl From<ed25519_dalek::SignatureError> for X3DHError {
    fn from(value: ed25519_dalek::SignatureError) -> Self {
        X3DHError::InvalidSignature(value)
    }
}


impl From<aes_gcm::Error> for X3DHError {
    fn from(value: aes_gcm::Error) -> Self {
        X3DHError::AesGcmError(value)
    }
}

impl From<crypto_common::InvalidLength> for X3DHError {
    fn from(value: crypto_common::InvalidLength) -> Self {
        X3DHError::AesGcmInvalidLength(value)
    }
}

impl From<base64::DecodeError> for X3DHError {
    fn from(value: base64::DecodeError) -> Self {
        X3DHError::Base64DecodeError(value)
    }
}

