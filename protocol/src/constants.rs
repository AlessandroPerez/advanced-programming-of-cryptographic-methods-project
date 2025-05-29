//! This module defines various cryptographic constants used throughout the protocol implementation.
//! These constants specify fixed byte lengths for keys, hashes, nonces, and other cryptographic primitives,
//! ensuring consistent sizing and preventing common errors related to buffer overflows or incorrect key derivations.

/// Byte size of a Curve25519 private key.
pub(crate) const CURVE25519_SECRET_LENGTH: usize = 32;

/// Byte size of a Curve25519 public key.
pub(crate) const CURVE25519_PUBLIC_LENGTH: usize = CURVE25519_SECRET_LENGTH;

/// Byte size of a signature.
pub(crate) const SIGNATURE_LENGTH: usize = 64;

/// Byte size of a SHA-256 hash.
pub(crate) const SHA256_HASH_LENGTH: usize = 32;

/// Byte size of an AES-256 key.
pub(crate) const AES256_SECRET_LENGTH: usize = 32;

/// Byte size of an AES-256 nonce.
pub const AES256_NONCE_LENGTH: usize = 12;

/// Byte size of a challenge.
pub(crate) const CHALLENGE_LENGTH: usize = 48;

/// Maximum number of allowed skips.
pub(crate) const MAX_SKIPS: u64 = 1000;
