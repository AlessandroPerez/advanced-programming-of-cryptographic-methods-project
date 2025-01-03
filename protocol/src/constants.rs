
// byte size of a Curve25519 private key
pub(crate) const CURVE25519_SECRET_LENGTH: usize = 32;
// byte size of a Curve25519 public key
pub(crate) const CURVE25519_PUBLIC_LENGTH: usize = CURVE25519_SECRET_LENGTH;

pub(crate) const SIGNATURE_LENGTH: usize = 64;
// byte size of a sha256 hash
pub(crate) const SHA256_HASH_LENGTH: usize = 32;
// byte size of an aes256 key
pub(crate) const AES256_SECRET_LENGTH: usize = 32;
// byte size of aes256 nonce
pub(crate) const AES256_NONCE_LENGTH: usize = 12;