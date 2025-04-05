use crate::constants::{AES256_NONCE_LENGTH, AES256_SECRET_LENGTH, CHALLENGE_LENGTH, CURVE25519_PUBLIC_LENGTH, CURVE25519_SECRET_LENGTH, SHA256_HASH_LENGTH, SIGNATURE_LENGTH};
use crate::errors::X3DHError;
use aes_gcm::aead::{Aead, Buffer, Payload};
use aes_gcm::{aead, AeadCore, Aes256Gcm, KeyInit, Nonce};
use arrayref::array_ref;
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::Verifier;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_bytes;
use sha2::{Digest, Sha256};
use std::hash::{Hash, Hasher};
use rand::Rng;
use x25519_dalek::StaticSecret;
use zeroize::{Zeroize, ZeroizeOnDrop};

/* PREKEY BUNDLE */
#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    pub verifying_key: VerifyingKey, // verifying key -> derived from the private identity signing key
    pub ik: PublicKey,               // identity key
    pub spk: PublicKey,              // signed pre-key
    pub sig: Signature,              // signature
    pub otpk: Vec<PublicKey>,        // one-time pre-keys
}

impl PreKeyBundle {
    pub(crate) const BASE_SIZE: usize = CURVE25519_PUBLIC_LENGTH
        + CURVE25519_PUBLIC_LENGTH
        + CURVE25519_PUBLIC_LENGTH
        + SIGNATURE_LENGTH;
    pub fn new(ik: &PrivateKey, spk: PublicKey) -> Self {
        let ik_signing = SigningKey::from(ik);
        let sig = ik_signing.sign(&spk.0);
        PreKeyBundle {
            verifying_key: VerifyingKey::from(&ik_signing),
            ik: PublicKey::from(ik),
            spk,
            sig,
            otpk: vec![],
        }
    }

    pub fn new_with_otpk(ik: &PrivateKey, spk: PublicKey, otpk: Vec<PublicKey>) -> Self {
        let ik_signing = SigningKey::from(ik);
        let sig = ik_signing.sign(&spk.0);
        PreKeyBundle {
            verifying_key: VerifyingKey::from(&ik_signing),
            ik: PublicKey::from(ik),
            spk,
            sig,
            otpk,
        }
    }

    pub fn add_otpk(&mut self, otpk: PublicKey) {
        self.otpk.push(otpk);
    }

    pub fn size(&self) -> usize {
        CURVE25519_SECRET_LENGTH * 3 + SIGNATURE_LENGTH + self.otpk.len() * CURVE25519_PUBLIC_LENGTH
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.verifying_key.0.as_ref());
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

        let verifying_key = VerifyingKey(*array_ref![bytes, 0, CURVE25519_PUBLIC_LENGTH]);
        let identity_key = PublicKey(*array_ref![
            bytes,
            CURVE25519_PUBLIC_LENGTH,
            CURVE25519_PUBLIC_LENGTH
        ]);
        let signed_prekey = PublicKey(*array_ref![
            bytes,
            2 * CURVE25519_PUBLIC_LENGTH,
            CURVE25519_PUBLIC_LENGTH
        ]);
        let prekey_signature = Signature(*array_ref![
            bytes,
            3 * CURVE25519_PUBLIC_LENGTH,
            SIGNATURE_LENGTH
        ]);
        if bytes.len() > Self::BASE_SIZE {
            let mut one_time_keys = Vec::new();
            for i in 0..(bytes.len() - Self::BASE_SIZE) / CURVE25519_PUBLIC_LENGTH {
                let start = Self::BASE_SIZE + i * CURVE25519_PUBLIC_LENGTH;
                let one_time_prekey =
                    PublicKey(*array_ref![bytes, start, CURVE25519_PUBLIC_LENGTH]);
                one_time_keys.push(one_time_prekey);
            }
            Ok(Self {
                verifying_key,
                ik: identity_key,
                spk: signed_prekey,
                sig: prekey_signature,
                otpk: one_time_keys,
            })
        } else {
            Ok(Self {
                verifying_key,
                ik: identity_key,
                spk: signed_prekey,
                sig: prekey_signature,
                otpk: vec![],
            })
        }
    }
}




/* SESSION KEYS */
#[derive(Clone)]
pub struct SessionKeys {
    ek: Option<EncryptionKey>,
    dk: Option<DecryptionKey>,

    aad: Option<AssociatedData>,
}

impl SessionKeys {
    pub fn new() -> Self {
        Self {
            ek: None,
            dk: None,
            aad: None,
        }
    }

    pub fn new_with_keys(
        ek: EncryptionKey,
        dk: DecryptionKey,
        aad: Option<AssociatedData>,
    ) -> Self {
        Self {
            ek: Some(ek),
            dk: Some(dk),
            aad,
        }
    }

    pub fn get_encryption_key(&self) -> Option<EncryptionKey> {
        self.ek.clone()
    }

    pub fn get_decryption_key(&self) -> Option<DecryptionKey> {
        self.dk.clone()
    }

    pub fn get_associated_data(&self) -> Option<AssociatedData> {
        self.aad.clone()
    }

    pub fn set_encryption_key(&mut self, ek: EncryptionKey) {
        self.ek = Some(ek);
    }

    pub fn set_decryption_key(&mut self, dk: DecryptionKey) {
        self.dk = Some(dk);
    }

    pub fn set_associated_data(&mut self, aad: AssociatedData) {
        self.aad = Some(aad);
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
#[derive(Clone, Debug)]
pub struct VerifyingKey( pub [u8; CURVE25519_PUBLIC_LENGTH]);

impl From<SigningKey> for VerifyingKey {
    fn from(private_key: SigningKey) -> VerifyingKey {
        let dalek_private_key = ed25519_dalek::SigningKey::from(private_key.0);
        let dalek_public_key = ed25519_dalek::VerifyingKey::from(&dalek_private_key);
        VerifyingKey(dalek_public_key.to_bytes())
    }
}

impl From<&SigningKey> for VerifyingKey {
    fn from(private_key: &SigningKey) -> VerifyingKey {
        let dalek_private_key = ed25519_dalek::SigningKey::from(private_key.0);
        let dalek_public_key = ed25519_dalek::VerifyingKey::from(&dalek_private_key);
        VerifyingKey(dalek_public_key.to_bytes())
    }
}

impl From<PublicKey> for VerifyingKey {
    fn from(public_key: PublicKey) -> VerifyingKey {
        VerifyingKey(public_key.0)
    }
}

impl From<&PublicKey> for VerifyingKey {
    fn from(public_key: &PublicKey) -> VerifyingKey {
        VerifyingKey(public_key.0)
    }
}

impl AsRef<[u8; CURVE25519_PUBLIC_LENGTH]> for VerifyingKey {
    fn as_ref(&self) -> &[u8; CURVE25519_PUBLIC_LENGTH] {
        &self.0
    }
}

impl VerifyingKey {
    pub(crate) fn verify(
        &self,
        signature: &Signature,
        message: &[u8],
    ) -> Result<(), ed25519_dalek::SignatureError> {
        let dalek_public_key = ed25519_dalek::VerifyingKey::from_bytes(&self.0)?;
        let dalek_signature = ed25519_dalek::Signature::from(signature.0);
        dalek_public_key.verify(message, &dalek_signature)
    }
}

/* SIGNING KEY */
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct SigningKey([u8; CURVE25519_PUBLIC_LENGTH]);

impl SigningKey {
    pub(crate) fn new() -> SigningKey {
        let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        SigningKey(key.to_bytes())
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

impl From<PrivateKey> for SigningKey {
    fn from(private_key: PrivateKey) -> SigningKey {
        SigningKey(private_key.0)
    }
}
impl From<&PrivateKey> for SigningKey {
    fn from(private_key: &PrivateKey) -> SigningKey {
        SigningKey(private_key.0)
    }
}

/* SIGNED PREKEY */
#[derive(Clone)]
pub(crate) struct SignedPreKey {
    pub(crate) private_key: PrivateKey,
    pub(crate) public_key: PublicKey,
}

impl SignedPreKey {
    pub(crate) fn new() -> SignedPreKey {
        let private_key = PrivateKey::new();
        let public_key = PublicKey::from(&private_key);
        SignedPreKey {
            private_key,
            public_key,
        }
    }
}

/* EPHEMERAL PRIVATE KEY */
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey([u8; CURVE25519_SECRET_LENGTH]);

impl PrivateKey {
    pub fn new() -> PrivateKey {
        let key = StaticSecret::random_from_rng(&mut OsRng);
        PrivateKey(key.to_bytes())
    }
    pub(crate) fn diffie_hellman(&self, public_key: &PublicKey) -> SharedSecret {
        let dalek_private_key = StaticSecret::from(self.0);
        let dalek_public_key = x25519_dalek::PublicKey::from(public_key.0);
        let shared_secret = dalek_private_key.diffie_hellman(&dalek_public_key);
        SharedSecret(shared_secret.to_bytes())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn to_base64(&self) -> String {
        general_purpose::STANDARD.encode(self.to_bytes())
    }

    pub fn from_base64(value: String) -> Result<PrivateKey, X3DHError> {
        let bytes = general_purpose::STANDARD.decode(value)?;
        if bytes.len() != CURVE25519_SECRET_LENGTH {
            return Err(X3DHError::InvalidPrivateKey);
        }
        let mut arr = [0u8; CURVE25519_SECRET_LENGTH];
        arr.copy_from_slice(&bytes);
        Ok(PrivateKey(arr))
    }
}

impl AsRef<[u8; CURVE25519_SECRET_LENGTH]> for PrivateKey {
    fn as_ref(&self) -> &[u8; CURVE25519_SECRET_LENGTH] {
        &self.0
    }
}

impl From<SigningKey> for PrivateKey {
    fn from(private_key: SigningKey) -> PrivateKey {
        let dalek_private_key = StaticSecret::from(private_key.0);
        PrivateKey(dalek_private_key.to_bytes())
    }
}

impl From<&SigningKey> for PrivateKey {
    fn from(private_key: &SigningKey) -> PrivateKey {
        let dalek_private_key = StaticSecret::from(private_key.0);
        PrivateKey(dalek_private_key.to_bytes())
    }
}

/* PUBLIC KEY */
#[derive(Clone, Debug)]
pub struct PublicKey( pub [u8; CURVE25519_PUBLIC_LENGTH]);

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

impl From<VerifyingKey> for PublicKey {
    fn from(public_key: VerifyingKey) -> PublicKey {
        PublicKey(public_key.0)
    }
}

impl From<&VerifyingKey> for PublicKey {
    fn from(public_key: &VerifyingKey) -> PublicKey {
        PublicKey(public_key.0)
    }
}

impl From<SigningKey> for PublicKey {
    fn from(value: SigningKey) -> Self {
        let key = VerifyingKey::from(&value);
        PublicKey::from(key)
    }
}

impl From<&SigningKey> for PublicKey {
    fn from(value: &SigningKey) -> Self {
        let key = VerifyingKey::from(value);
        PublicKey::from(key)
    }
}

impl AsRef<[u8; CURVE25519_PUBLIC_LENGTH]> for PublicKey {
    fn as_ref(&self) -> &[u8; CURVE25519_PUBLIC_LENGTH] {
        &self.0
    }
}

impl PublicKey {
    pub fn hash(&self) -> Sha256Hash {
        let digest = Sha256::digest(self.0.as_ref());
        Sha256Hash(*array_ref![digest, 0, SHA256_HASH_LENGTH])
    }

    pub fn to_base64(&self) -> String {
        general_purpose::STANDARD.encode(self.0.to_vec())
    }

    pub fn from_base64(value: String) -> Result<PublicKey, X3DHError> {
        let bytes = general_purpose::STANDARD.decode(value)?;
        if bytes.len() != CURVE25519_PUBLIC_LENGTH {
            return Err(X3DHError::InvalidPublicKey);
        }
        let mut arr = [0u8; CURVE25519_PUBLIC_LENGTH];
        arr.copy_from_slice(&bytes);
        Ok(PublicKey(arr))
    }
}

/* SIGNATURE */
#[derive(Clone, Debug)]
pub struct Signature( pub [u8; SIGNATURE_LENGTH]);

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

/* ASSOCIATED DATA */
#[derive(Clone, Debug)]
pub struct AssociatedData {
    pub(crate) initiator_identity_key: PublicKey,
    pub(crate) responder_identity_key: PublicKey,
}

impl AssociatedData {
    pub const SIZE: usize = CURVE25519_PUBLIC_LENGTH + CURVE25519_PUBLIC_LENGTH;
    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.initiator_identity_key.0.as_ref());
        out.extend_from_slice(self.responder_identity_key.0.as_ref());
        out
    }

    pub fn new(ik: PublicKey, spk: PublicKey) -> Self {
        Self {
            initiator_identity_key: ik,
            responder_identity_key: spk,
        }
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
#[derive(Clone, Eq, Debug)]
pub struct Sha256Hash(pub [u8; SHA256_HASH_LENGTH]);

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

/* CHALLENGE */
#[derive(Clone, Debug)]
pub struct Challenge(pub(crate) [u8; CHALLENGE_LENGTH]);

impl From<&[u8; CHALLENGE_LENGTH]> for Challenge {
    fn from(value: &[u8; CHALLENGE_LENGTH]) -> Challenge {
        Challenge(*value)
    }
}

impl TryFrom<&[u8]> for Challenge {
    type Error = X3DHError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != CHALLENGE_LENGTH {
            return Err(X3DHError::InvalidChallenge)
        }
        let data = *array_ref!(value, 0, CHALLENGE_LENGTH);
        Ok(Challenge(data))
    }
}

/* INITIAL MESSAGE */
#[derive(Clone)]
pub struct InitialMessage {
    pub identity_key: PublicKey,
    pub ephemeral_key: PublicKey,
    pub prekey_hash: Sha256Hash,
    pub one_time_key_hash: Option<Sha256Hash>,
    pub challenge: Challenge,
    pub associated_data: AssociatedData,
}

impl InitialMessage {
    // the byte size of a prekey bundle
    pub(crate) const BASE_SIZE: usize = CURVE25519_PUBLIC_LENGTH
        + CURVE25519_PUBLIC_LENGTH
        + SHA256_HASH_LENGTH
        + CHALLENGE_LENGTH
        + CURVE25519_PUBLIC_LENGTH
        + CURVE25519_PUBLIC_LENGTH;

    pub(crate) const SIZE_WITH_OTPK: usize = Self::BASE_SIZE + SHA256_HASH_LENGTH;

    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.identity_key.0.as_ref());
        out.extend_from_slice(self.ephemeral_key.0.as_ref());
        out.extend_from_slice(self.prekey_hash.0.as_ref());

        if let Some(one_time_key_hash) = self.one_time_key_hash {
            out.extend_from_slice(one_time_key_hash.0.as_ref());
        }
        out.extend_from_slice(self.challenge.0.as_ref());
        out.extend_from_slice(self.associated_data.to_bytes().as_ref());
        out
    }

    pub fn to_base64(self) -> String {
        general_purpose::STANDARD.encode(self.to_bytes())
    }

    pub fn size(&self) -> usize {
        if self.one_time_key_hash.is_some() {
            Self::SIZE_WITH_OTPK
        } else {
            Self::BASE_SIZE
        }
    }
}

impl TryFrom<String> for InitialMessage {
    type Error = X3DHError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = general_purpose::STANDARD.decode(value)?;
        if bytes.len() != Self::BASE_SIZE && bytes.len() != Self::SIZE_WITH_OTPK {
            return Err(X3DHError::InvalidInitialMessage);
        }

        let identity_key = PublicKey(*array_ref![bytes, 0, CURVE25519_PUBLIC_LENGTH]);
        let ephemeral_key = PublicKey(*array_ref![
            bytes,
            CURVE25519_PUBLIC_LENGTH,
            CURVE25519_PUBLIC_LENGTH
        ]);
        let prekey_hash = Sha256Hash(*array_ref![
            bytes,
            2 * CURVE25519_PUBLIC_LENGTH,
            SHA256_HASH_LENGTH
        ]);

        if bytes.len() == Self::SIZE_WITH_OTPK {
            let one_time_key_hash = Sha256Hash(*array_ref![
                bytes,
                2 * CURVE25519_PUBLIC_LENGTH + SHA256_HASH_LENGTH,
                SHA256_HASH_LENGTH
            ]);
            let challenge = Challenge(*array_ref![
                bytes,
                2 * CURVE25519_PUBLIC_LENGTH + 2 * SHA256_HASH_LENGTH,
                CHALLENGE_LENGTH
            ]);
            let associated_data = AssociatedData::try_from(array_ref![
                bytes,
                2 * CURVE25519_PUBLIC_LENGTH + 2 * SHA256_HASH_LENGTH + CHALLENGE_LENGTH,
                2 * CURVE25519_PUBLIC_LENGTH
            ])?;

            Ok(Self {
                identity_key,
                ephemeral_key,
                prekey_hash,
                one_time_key_hash: Some(one_time_key_hash),
                challenge,
                associated_data,
            })
        } else {
            let challenge = Challenge(*array_ref![
                bytes,
                2 * CURVE25519_PUBLIC_LENGTH + SHA256_HASH_LENGTH,
                CHALLENGE_LENGTH
            ]);
            let associated_data = AssociatedData::try_from(array_ref![
                bytes,
                2 * CURVE25519_PUBLIC_LENGTH + SHA256_HASH_LENGTH + CHALLENGE_LENGTH,
                2 * CURVE25519_PUBLIC_LENGTH
            ])?;
            Ok(Self {
                identity_key,
                ephemeral_key,
                prekey_hash,
                one_time_key_hash: None,
                challenge,
                associated_data,
            })
        }
    }
}



/* Encryption Key */
#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct EncryptionKey([u8; AES256_SECRET_LENGTH]);

impl EncryptionKey {
    pub fn encrypt(&self, data: &[u8], aad: &AssociatedData) -> Result<String, X3DHError> {
        let nonce = &Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes256Gcm::new_from_slice(&self.0);
        let payload = Payload {
            aad: &aad.clone().to_bytes(),
            msg: data,
        };
        let encrypt_msg = cipher?.encrypt(nonce, payload)?;
        let mut output = vec![];
        output.extend_from_slice(&nonce.to_vec());
        output.extend_from_slice(&aad.clone().to_bytes());
        output.extend_from_slice(&encrypt_msg);
        let b64 = general_purpose::STANDARD.encode(output);

        Ok(b64)
    }

    pub(crate) fn encrypt_challenge(&self, data: &[u8]) -> Result<Challenge, X3DHError> {
        let nonce = b"hello world!";
        let nonce = Nonce::from_slice(nonce);
        let cipher = Aes256Gcm::new_from_slice(&self.0);
        let encrypt_msg = cipher?.encrypt(nonce, data)?;
        let mut output = vec![];
        output.extend_from_slice(encrypt_msg.as_ref());
        Ok(Challenge::try_from(output.as_slice())?)
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
#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct DecryptionKey([u8; AES256_SECRET_LENGTH]);

impl DecryptionKey {
    pub fn decrypt(
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

    pub(crate) fn decrypt_challenge(&self, data: &Challenge) -> Result<Vec<u8>, X3DHError> {
        let nonce = b"hello world!";
        let nonce = Nonce::from_slice(nonce);
        let cipher = Aes256Gcm::new_from_slice(&self.0);
        let output = cipher?.decrypt(nonce, data.0.as_ref())?;
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
    fn test_serde_prekey_bundle() {
        let ik1 = PrivateKey::new();
        let spk = SignedPreKey::new();

        let pb1 = PreKeyBundle::new(&ik1, spk.public_key);

        let b64 = pb1.clone().to_base64();
        let pb2 = PreKeyBundle::try_from(b64).unwrap();
        assert_eq!(pb1.ik.0, pb2.ik.0);
        assert_eq!(pb1.spk.0, pb2.spk.0);
        assert_eq!(pb1.sig.0, pb2.sig.0);
    }

    #[test]
    fn test_hash_public_key() {
        let key1 = PublicKey::from(PrivateKey::new());
        let key2 = PublicKey::from(PrivateKey::new());
        assert_ne!(key1.hash().0, key2.hash().0);
    }

    #[test]
    fn test_sign_verify() {
        let ik = SigningKey::new();
        let p_ik = VerifyingKey::from(&ik);
        let data = String::from("Hello World!!!");

        let sig = ik.sign(data.as_bytes());
        assert!(p_ik.verify(&sig, data.as_bytes()).is_ok());
    }
}
