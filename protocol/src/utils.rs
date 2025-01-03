use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::{SigningKey, Verifier};
use rand::rngs::OsRng;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_bytes;
use x25519_dalek::StaticSecret;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::constants::{
    CURVE25519_PUBLIC_LENGTH,
    SIGNATURE_LENGTH,
    SHA256_HASH_LENGTH,
    AES256_SECRET_LENGTH,
    AES256_NONCE_LENGTH,
    CURVE25519_SECRET_LENGTH,
};


/* PREKEY BUNDLE */
#[derive(Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub(crate) ik: IdentityPublicKey,       // identity key
    pub(crate) spk: PublicKey,      // signed prekey
    pub(crate) sig: Signature,      // signature
    pub(crate) otpk: Vec<PublicKey> // one-time prekeys
}

impl PreKeyBundle {
    pub fn new(ik: &IdentityPrivateKey, spk: PublicKey) -> Self {
        let sig = ik.sign(&spk.0);
        PreKeyBundle {
            ik: IdentityPublicKey::from(ik),
            spk,
            sig,
            otpk: vec![]
        }
    }
}

/* SHARED SECRET */
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct SharedSecret([u8; AES256_SECRET_LENGTH]);


/* VERIFYING KEY */
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub(crate) struct IdentityPublicKey(#[serde(with = "serde_bytes")] pub [u8; CURVE25519_PUBLIC_LENGTH]);

impl From<IdentityPrivateKey> for IdentityPublicKey {
    fn from(private_key: IdentityPrivateKey) -> IdentityPublicKey {
        let dalek_private_key = ed25519_dalek::SigningKey::from(private_key.0);
        let dalek_public_key = ed25519_dalek::VerifyingKey::from(&dalek_private_key);
        IdentityPublicKey(dalek_public_key.to_bytes())
    }
}

impl From<&IdentityPrivateKey> for IdentityPublicKey {
    fn from(private_key: &IdentityPrivateKey) -> IdentityPublicKey {
        let dalek_private_key = ed25519_dalek::SigningKey::from(private_key.0);
        let dalek_public_key = ed25519_dalek::VerifyingKey::from(&dalek_private_key);
        IdentityPublicKey(dalek_public_key.to_bytes())
    }
}

impl AsRef<[u8; CURVE25519_PUBLIC_LENGTH]> for IdentityPublicKey {
    fn as_ref(&self) -> &[u8; CURVE25519_PUBLIC_LENGTH] {
        &self.0
    }
}

impl IdentityPublicKey {
    pub(crate) fn verify(&self, signature: &Signature, message: &[u8]) -> Result<(), ed25519_dalek::SignatureError> {
        let dalek_public_key = ed25519_dalek::VerifyingKey::from_bytes(&self.0)?;
        let dalek_signature = ed25519_dalek::Signature::from(signature.0);
        dalek_public_key.verify(message, &dalek_signature)
    }
}

/* SIGNING KEY */
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct IdentityPrivateKey(#[serde(with = "serde_bytes")] pub [u8; CURVE25519_PUBLIC_LENGTH]);

impl IdentityPrivateKey {
    pub(crate) fn new() -> IdentityPrivateKey {
        let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        IdentityPrivateKey(key.to_bytes())
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Signature {
        let mut dalek_private_key = ed25519_dalek::SigningKey::from(self.0);
        let signature = dalek_private_key.sign(message);
        Signature(signature.to_bytes())
    }
}

/* PUBLIC KEY */
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub(crate) struct PublicKey(#[serde(with = "serde_bytes")] pub [u8; CURVE25519_PUBLIC_LENGTH]);

impl From<PrivateKey> for PublicKey {
    fn from(private_key: PrivateKey) -> PublicKey {
        let dalek_private_key = x25519_dalek::StaticSecret::from(private_key.0);
        let dalek_public_key = x25519_dalek::PublicKey::from(&dalek_private_key);
        PublicKey(dalek_public_key.to_bytes())
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(private_key: &PrivateKey) -> PublicKey {
        let dalek_private_key = x25519_dalek::StaticSecret::from(private_key.0);
        let dalek_public_key = x25519_dalek::PublicKey::from(&dalek_private_key);
        PublicKey(dalek_public_key.to_bytes())
    }
}

impl AsRef<[u8; CURVE25519_PUBLIC_LENGTH]> for PublicKey {
    fn as_ref(&self) -> &[u8; CURVE25519_PUBLIC_LENGTH] {
        &self.0
    }
}

/* SIGNATURE */
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub(crate) struct Signature(#[serde(with = "serde_bytes")] pub [u8; SIGNATURE_LENGTH]);

impl AsRef<[u8; SIGNATURE_LENGTH]> for Signature {
    fn as_ref(&self) -> &[u8; SIGNATURE_LENGTH] {
        &self.0
    }
}

impl From<[u8; SIGNATURE_LENGTH]> for Signature {
    fn from(value: [u8; SIGNATURE_LENGTH]) -> Signature {
        Signature(value)
    }
}

/* EPHEMERAL PRIVATE KEY */
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct PrivateKey([u8; CURVE25519_SECRET_LENGTH]);

impl PrivateKey {
    pub(crate) fn new() -> PrivateKey {
        let key = StaticSecret::random_from_rng(&mut OsRng);
        PrivateKey(key.to_bytes())
    }
    pub(crate) fn diffie_hellman(&self, public_key: &PublicKey) -> SharedSecret {
        let dalek_private_key = StaticSecret::from(self.0);
        let dalek_public_key = x25519_dalek::PublicKey::from(public_key.0);
        let shared_secret = dalek_private_key.diffie_hellman(&dalek_public_key);
        SharedSecret(shared_secret.to_bytes())
    }
}

impl AsRef<[u8; CURVE25519_SECRET_LENGTH]> for PrivateKey {
    fn as_ref(&self) -> &[u8; CURVE25519_SECRET_LENGTH] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let ik = IdentityPrivateKey::new();
        let p_ik = IdentityPublicKey::from(&ik);
        let data = String::from("Hello World!!!");

        let sig = ik.sign(data.as_bytes());
        assert!(p_ik.verify(&sig, data.as_bytes()).unwrap());
    }
}