//! This module defines the custom error types used throughout the cryptographic protocol implementation.
//! It provides two main error enums: `X3DHError` for errors specific to the X3DH key agreement protocol,
//! and `RatchetError` for errors encountered during the Double Ratchet message encryption protocol.
//! These enums ensure precise error reporting and handling for various cryptographic operations.

use aes::cipher::crypto_common;
use ed25519_dalek::SignatureError;
use std::fmt::{Display, Formatter};

/// Represents errors that can occur during the X3DH key agreement protocol.
#[derive(Debug)]
pub enum X3DHError {

    /// Error occurring during signature verification with Ed25519.
    InvalidSignature(SignatureError),
    
    /// Error indicating an invalid key material length during HKDF key derivation.
    HkdfInvalidLengthError(hkdf::InvalidLength),
    
    /// Error indicating an invalid length for AES-GCM encryption or decryption.
    AesGcmInvalidLength(crypto_common::InvalidLength),
    
    /// General AES-GCM encryption or decryption error.
    AesGcmError(aes_gcm::Error),
    
    /// Error occurring during Base64 decoding of encoded data.
    Base64DecodeError(base64::DecodeError),
    
    /// Error indicating that a [`crate::utils::PreKeyBundle`] is invalid or corrupted.
    InvalidPreKeyBundle,
    
    /// Error indicating that an [`crate::utils::InitialMessage`] is invalid or corrupted.
    InvalidInitialMessage,
    
    /// Error indicating an invalid or corrupted [`crate::utils::PrivateKey`].
    InvalidPrivateKey,
    
    /// Error indicating an invalid or corrupted [`crate::utils::PublicKey`].
    InvalidPublicKey,
    
    /// Error indicating a general key validation failure.
    InvalidKey,
    
    /// Error indicating that the challenge in the X3DH protocol is invalid.
    InvalidChallenge,
}

impl Display for X3DHError {
    /// Formats the error message for display.
    ///
    /// # Arguments
    ///
    /// * `f` - A formatter used to write the error message.
    ///
    /// # Returns
    ///
    /// * `fmt::Result` - Indicating whether the operation succeeded or failed.
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            X3DHError::InvalidSignature(e) => write!(f, "Invalid signature: {}", e),
            X3DHError::HkdfInvalidLengthError(e) => write!(f, "Invalid length: {}", e),
            X3DHError::AesGcmError(e) => write!(f, "AES GCM error: {}", e),
            X3DHError::AesGcmInvalidLength(e) => write!(f, "Invalid length: {}", e),
            X3DHError::Base64DecodeError(e) => write!(f, "Base64 decode error: {}", e),
            X3DHError::InvalidPreKeyBundle => write!(f, "Invalid prekey bundle"),
            X3DHError::InvalidInitialMessage => write!(f, "Invalid initial message"),
            X3DHError::InvalidPrivateKey => write!(f, "Invalid private key"),
            X3DHError::InvalidPublicKey => write!(f, "Invalid public key"),
            X3DHError::InvalidKey => write!(f, "Invalid key"),
            X3DHError::InvalidChallenge => write!(f, "Invalid challenge length")
        }
    }
}

/// Implements the standard error trait for [`X3DHError`].
impl std::error::Error for X3DHError {}

/// Conversion from HKDF InvalidLength error to [`X3DHError::HkdfInvalidLengthError`].
impl From<hkdf::InvalidLength> for X3DHError {
    fn from(value: hkdf::InvalidLength) -> Self {
        X3DHError::HkdfInvalidLengthError(value)
    }
}

/// Conversion from Ed25519 SignatureError to [`X3DHError::InvalidSignature`].
impl From<ed25519_dalek::SignatureError> for X3DHError {
    fn from(value: ed25519_dalek::SignatureError) -> Self {
        X3DHError::InvalidSignature(value)
    }
}

/// Conversion from AES-GCM Error to [`X3DHError::AesGcmError`].
impl From<aes_gcm::Error> for X3DHError {
    fn from(value: aes_gcm::Error) -> Self {
        X3DHError::AesGcmError(value)
    }
}

/// Conversion from crypto_common InvalidLength error to [`X3DHError::AesGcmInvalidLength`].
impl From<crypto_common::InvalidLength> for X3DHError {
    fn from(value: crypto_common::InvalidLength) -> Self {
        X3DHError::AesGcmInvalidLength(value)
    }
}

/// Conversion from Base64 DecodeError to [`X3DHError::Base64DecodeError`].
impl From<base64::DecodeError> for X3DHError {
    fn from(value: base64::DecodeError) -> Self {
        X3DHError::Base64DecodeError(value)
    }
}

/// Represents errors that can occur during the Double Ratchet protocol.
#[derive(Debug)]
pub enum RatchetError {
    /// Error indicating an invalid key material length during HKDF key derivation.
    HkdfInvalidLengthError(hkdf::InvalidLength),
    
    /// Error indicating an invalid message header length.
    InvalidHeaderLength(usize),
    
    /// Error occurring during message decryption, wrapping an X3DHError.
    DecryptionError(X3DHError),
    
    /// Error indicating that the maximum number of skipped messages has been exceeded,
    /// which could indicate a replay attack.
    MaxSkipsExceeded,
    
    /// Error indicating a failure in data type conversion.
    ConversionError,
}

impl Display for RatchetError {
    /// Formats the error message for display.
    ///
    /// # Arguments
    ///
    /// * `f` - A formatter used to write the error message.
    ///
    /// # Returns
    ///
    /// * `fmt::Result` - Indicating whether the operation succeeded or failed.
    /// 
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            RatchetError::HkdfInvalidLengthError(e) => write!(f, "Invalid length: {}", e),
            RatchetError::InvalidHeaderLength(e) => write!(f, "Invalid header length: {}", e),
            RatchetError::DecryptionError(e) => write!(f, "Decryption error: {}", e),
            RatchetError::MaxSkipsExceeded => write!(f, "Max skips exceeded"),
            RatchetError::ConversionError => write!(f, "Conversion error"),
        }
    }
}

/// Implements the standard error trait for RatchetError.
impl std::error::Error for RatchetError {}

/// Conversion from HKDF InvalidLength error to [`RatchetError::HkdfInvalidLengthError`].
impl From<hkdf::InvalidLength> for RatchetError {
    fn from(value: hkdf::InvalidLength) -> Self {
        RatchetError::HkdfInvalidLengthError(value)
    }
}

/// Conversion from X3DHError to [`RatchetError::DecryptionError`].
impl From<X3DHError> for RatchetError {
    fn from(value: X3DHError) -> Self {
        RatchetError::DecryptionError(value)
    }
}