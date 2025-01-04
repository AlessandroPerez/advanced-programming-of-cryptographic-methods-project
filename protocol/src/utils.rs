use std::hash::{Hash, Hasher};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, Payload};
use arrayref::array_ref;
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::Verifier;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_bytes;
use x25519_dalek::StaticSecret;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::constants::{CURVE25519_PUBLIC_LENGTH, SIGNATURE_LENGTH, AES256_SECRET_LENGTH, CURVE25519_SECRET_LENGTH, SHA256_HASH_LENGTH, AES256_NONCE_LENGTH};
use crate::errors::X3DHError;
use base64::{Engine as _, engine:: general_purpose};
use sha2::{Digest, Sha256};
/* PREKEY BUNDLE */
#[derive(Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub(crate) verifying_key: IdentityPublicKey,
    pub(crate) ik: PublicKey,       // identity key
    pub(crate) spk: PublicKey,              // signed prekey
    pub(crate) sig: Signature,              // signature
    pub(crate) otpk: Vec<PublicKey>         // one-time prekeys
}

impl PreKeyBundle {
    pub(crate) const BASE_SIZE: usize = CURVE25519_PUBLIC_LENGTH + CURVE25519_PUBLIC_LENGTH + SIGNATURE_LENGTH;
    pub fn new(ik: &PrivateKey, spk: PublicKey) -> Self {
        let ik_signing = IdentityPrivateKey::from(ik);
        let sig = ik_signing.sign(&spk.0);
        PreKeyBundle {
            verifying_key: IdentityPublicKey::from(&ik_signing),
            ik: PublicKey::from(ik),
            spk,
            sig,
            otpk: vec![]
        }
    }

    pub fn add_otpk(&mut self, otpk: PublicKey) {
        self.otpk.push(otpk);
    }

    pub fn size(&self) -> usize {
        CURVE25519_SECRET_LENGTH +
        CURVE25519_PUBLIC_LENGTH +
        SIGNATURE_LENGTH +
        self.otpk.len() * CURVE25519_PUBLIC_LENGTH
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.ik.0.as_ref());
        out.extend_from_slice(self.spk.0.as_ref());
        out.extend_from_slice(self.sig.0.as_ref());
        if !self.otpk.is_empty() {
            for i in 0..self.otpk.len() {
                out.extend_from_slice(self.otpk[i].0.as_ref());
            }
        }
        out
    }

    pub fn to_base64(self) -> String {
        general_purpose::STANDARD.encode(self.to_bytes())
    }
}

impl TryFrom<String> for PreKeyBundle {
    type Error = X3DHError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = general_purpose::STANDARD.decode(value)?;
        if bytes.len() < Self::BASE_SIZE {
            return Err(X3DHError::InvalidPreKeyBundle);
        }

        let verifying_key = IdentityPublicKey(*array_ref![bytes, 0, CURVE25519_PUBLIC_LENGTH]);
        let identity_key = PublicKey(*array_ref![bytes, 0, CURVE25519_PUBLIC_LENGTH]);
        let signed_prekey = PublicKey(*array_ref![
            bytes,
            CURVE25519_PUBLIC_LENGTH,
            CURVE25519_PUBLIC_LENGTH
        ]);
        let prekey_signature = Signature(*array_ref![
            bytes,
            2 * CURVE25519_PUBLIC_LENGTH,
            SIGNATURE_LENGTH
        ]);
        if bytes.len() > Self::BASE_SIZE {
            let mut one_time_keys = Vec::new();
            for i in 0..(bytes.len() - Self::BASE_SIZE) / CURVE25519_PUBLIC_LENGTH {
                let start = Self::BASE_SIZE + i * CURVE25519_PUBLIC_LENGTH;
                let one_time_prekey = PublicKey(*array_ref![bytes, start, CURVE25519_PUBLIC_LENGTH]);
                one_time_keys.push(one_time_prekey);
            }
            Ok(Self {
                verifying_key,
                ik: identity_key,
                spk: signed_prekey,
                sig: prekey_signature,
                otpk: one_time_keys
            })
        } else {
            Ok(Self {
                verifying_key,
                ik: identity_key,
                spk: signed_prekey,
                sig: prekey_signature,
                otpk: vec![]
            })
        }
    }
}

/* SHARED SECRET */
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct SharedSecret([u8; AES256_SECRET_LENGTH]);

impl AsRef<[u8; AES256_SECRET_LENGTH]> for SharedSecret {
    fn as_ref(&self) -> &[u8; AES256_SECRET_LENGTH] {
        &self.0
    }
}

impl From<[u8; AES256_SECRET_LENGTH]> for SharedSecret {
    fn from(value: [u8; AES256_SECRET_LENGTH]) -> SharedSecret {
        SharedSecret(value)
    }
}


/* VERIFYING KEY */
#[derive(Clone, Serialize, Deserialize)]
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

impl From<PublicKey> for IdentityPublicKey {
    fn from(public_key: PublicKey) -> IdentityPublicKey {
        IdentityPublicKey(public_key.0)
    }

}

impl From<&PublicKey> for IdentityPublicKey {
    fn from(public_key: &PublicKey) -> IdentityPublicKey {
        IdentityPublicKey(public_key.0)
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
pub(crate) struct IdentityPrivateKey([u8; CURVE25519_PUBLIC_LENGTH]);

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

    pub(crate) fn diffie_hellman(&self, public_key: &PublicKey) -> SharedSecret {
        let dalek_private_key = StaticSecret::from(self.0);
        let dalek_public_key = x25519_dalek::PublicKey::from(public_key.0);
        let shared_secret = dalek_private_key.diffie_hellman(&dalek_public_key);
        SharedSecret(shared_secret.to_bytes())
    }
}

impl From<PrivateKey> for IdentityPrivateKey {
    fn from(private_key: PrivateKey) -> IdentityPrivateKey {
        IdentityPrivateKey(private_key.0)
    }
}impl From<&PrivateKey> for IdentityPrivateKey {
    fn from(private_key: &PrivateKey) -> IdentityPrivateKey {
        IdentityPrivateKey(private_key.0)
    }
}

/* PUBLIC KEY */
#[derive(Clone, Serialize, Deserialize)]
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

impl From<IdentityPublicKey> for PublicKey {
    fn from(public_key: IdentityPublicKey) -> PublicKey {
        PublicKey(public_key.0)
    }
}

impl From<&IdentityPublicKey> for PublicKey {
    fn from(public_key: &IdentityPublicKey) -> PublicKey {
        PublicKey(public_key.0)
    }
}

impl From<IdentityPrivateKey> for PublicKey {
    fn from(value: IdentityPrivateKey) -> Self {
        let key = IdentityPublicKey::from(&value);
        PublicKey::from(key)
    }
}

impl From<&IdentityPrivateKey> for PublicKey {
    fn from(value: &IdentityPrivateKey) -> Self {
        let key = IdentityPublicKey::from(value);
        PublicKey::from(key)
    }
}

impl AsRef<[u8; CURVE25519_PUBLIC_LENGTH]> for PublicKey {
    fn as_ref(&self) -> &[u8; CURVE25519_PUBLIC_LENGTH] {
        &self.0
    }
}

impl PublicKey {
    pub(crate) fn hash(&self) -> Sha256Hash {
        let digest = Sha256::digest(self.0.as_ref());
        Sha256Hash(*array_ref![digest, 0, SHA256_HASH_LENGTH])
    }
}

/* SIGNATURE */
#[derive(Clone, Serialize, Deserialize)]
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

impl From<IdentityPrivateKey> for PrivateKey {
    fn from(private_key: IdentityPrivateKey) -> PrivateKey {
        let dalek_private_key = StaticSecret::from(private_key.0);
        PrivateKey(dalek_private_key.to_bytes())
    }
}

impl From<&IdentityPrivateKey> for PrivateKey {
    fn from(private_key: &IdentityPrivateKey) -> PrivateKey {
        let dalek_private_key = StaticSecret::from(private_key.0);
        PrivateKey(dalek_private_key.to_bytes())
    }
}

/* ASSOCIATED DATA */
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AssociatedData {
    pub(crate) initiator_identity_key: PublicKey,
    pub(crate) responder_identity_key: PublicKey,
}

impl AssociatedData {
    pub(crate) const SIZE: usize = CURVE25519_PUBLIC_LENGTH + CURVE25519_PUBLIC_LENGTH;
    pub(crate) fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.initiator_identity_key.0.as_ref());
        out.extend_from_slice(self.responder_identity_key.0.as_ref());
        out
    }
}

impl TryFrom<&[u8; Self::SIZE]> for AssociatedData {
    type Error = X3DHError;
    fn try_from(value: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let initiator_identity_key = PublicKey(*array_ref![value, 0, CURVE25519_PUBLIC_LENGTH]);
        let responder_identity_key = PublicKey(*array_ref![
            value,
            CURVE25519_PUBLIC_LENGTH,
            CURVE25519_PUBLIC_LENGTH
        ]);
        Ok(AssociatedData {
            initiator_identity_key,
            responder_identity_key,
        })
    }
}

/* SHA HASH */
#[derive(Clone, Serialize, Deserialize, Eq)]
pub struct Sha256Hash(#[serde(with = "serde_bytes")] pub [u8; SHA256_HASH_LENGTH]);

impl From<&[u8; SHA256_HASH_LENGTH]> for Sha256Hash {
    fn from(value: &[u8; SHA256_HASH_LENGTH]) -> Sha256Hash {
        Sha256Hash(*value)
    }
}
impl Hash for Sha256Hash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialEq for Sha256Hash {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/* INITIAL MESSAGE */
#[derive(Clone, Serialize, Deserialize)]
pub struct InitialMessage {
    pub(crate) identity_key: PublicKey,
    pub(crate) ephemeral_key: PublicKey,
    pub(crate) prekey_hash: Sha256Hash,
    pub(crate) one_time_key_hash: Option<Sha256Hash>,
    pub(crate) associated_data: AssociatedData,
}

impl InitialMessage {
    // the byte size of a prekey bundle
    pub(crate) const BASE_SIZE: usize = CURVE25519_PUBLIC_LENGTH
        + CURVE25519_PUBLIC_LENGTH
        + SHA256_HASH_LENGTH
        + CURVE25519_PUBLIC_LENGTH
        + CURVE25519_PUBLIC_LENGTH;

    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.identity_key.0.as_ref());
        out.extend_from_slice(self.ephemeral_key.0.as_ref());
        out.extend_from_slice(self.prekey_hash.0.as_ref());
        if let Some(one_time_key_hash) = self.one_time_key_hash {
            out.extend_from_slice(one_time_key_hash.0.as_ref());
        }
        out.extend_from_slice(self.associated_data.to_bytes().as_ref());
        out
    }

    pub fn to_base64(self) -> String {
        general_purpose::STANDARD.encode(self.to_bytes())
    }

    pub fn size(&self) -> usize {
        Self::BASE_SIZE + if self.one_time_key_hash.is_some() {SHA256_HASH_LENGTH} else {0}
    }
}

/* Encryption Key */
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct EncryptionKey([u8; AES256_SECRET_LENGTH]);

impl EncryptionKey {
    pub(crate) fn encrypt(
        &self,
        data: &[u8],
        nonce: &[u8; AES256_NONCE_LENGTH],
        aad: &AssociatedData,
    ) -> Result<Vec<u8>, X3DHError> {
        let cipher = Aes256Gcm::new_from_slice(&self.0);
        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            aad: &aad.clone().to_bytes(),
            msg: data,
        };
        let output = cipher?.encrypt(nonce, payload)?;
        Ok(output)
    }
}

impl From<SharedSecret> for EncryptionKey {
    fn from(value: SharedSecret) -> EncryptionKey {
        EncryptionKey(value.0)
    }
}

impl AsRef<[u8; AES256_SECRET_LENGTH]> for EncryptionKey {
    fn as_ref(&self) -> &[u8; AES256_SECRET_LENGTH] {
        &self.0
    }
}

/* Decryption Key */
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct DecryptionKey([u8; AES256_SECRET_LENGTH]);

impl DecryptionKey {
    pub(crate) fn decrypt(
        &self,
        data: &[u8],
        nonce: &[u8; AES256_NONCE_LENGTH],
        aad: &AssociatedData,
    ) -> Result<Vec<u8>, X3DHError> {
        let cipher = Aes256Gcm::new_from_slice(&self.0);
        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            aad: &aad.clone().to_bytes(),
            msg: data,
        };
        let output = cipher?.decrypt(nonce, payload)?;
        Ok(output)
    }
}

impl From<SharedSecret> for DecryptionKey {
    fn from(value: SharedSecret) -> DecryptionKey {
        DecryptionKey(value.0)
    }
}

impl AsRef<[u8; AES256_SECRET_LENGTH]> for DecryptionKey {
    fn as_ref(&self) -> &[u8; AES256_SECRET_LENGTH] {
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
        assert!(p_ik.verify(&sig, data.as_bytes()).is_ok());
    }
}