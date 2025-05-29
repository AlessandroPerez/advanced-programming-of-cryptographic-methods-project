//! This module provides a collection of utility structures and helper functions essential for the cryptographic protocols.
//! It defines fundamental data types such as `PublicKey`, `PrivateKey`, `SharedSecret`, `Signature`, and `AssociatedData`,
//! along with their serialization, deserialization, and cryptographic operations (e.g., hashing, encryption, decryption).
//! These utilities encapsulate common cryptographic operations and data representations,
//! supporting the X3DH and Double Ratchet implementations.

use crate::constants::{AES256_NONCE_LENGTH, AES256_SECRET_LENGTH, CHALLENGE_LENGTH, CURVE25519_PUBLIC_LENGTH, CURVE25519_SECRET_LENGTH, SHA256_HASH_LENGTH, SIGNATURE_LENGTH};
use crate::errors::X3DHError;
use aes_gcm::aead::{Aead, Buffer, Payload};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, Nonce};
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

/// A [`PreKeyBundle`] contains the public keys and signature published by a recipient,
/// used by an initiator to establish a shared secret using the X3DH key agreement protocol.
#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    /// The recipient's identity signing key (Ed25519), used to verify `sig`.
    /// For more information, see [`VerifyingKey`].
    pub verifying_key: VerifyingKey,

    /// The recipient's identity public key.
    /// For more information, see [`PublicKey`].
    pub ik: PublicKey,

    /// The recipient's signed public pre-key.
    /// For more information, see [`PublicKey`].
    pub spk: PublicKey,

    /// A signature of the `spk`, signed by the identity signing key.
    /// For more information, see [`Signature`].
    pub sig: Signature,

    /// One or more ephemeral one-time pre-keys, X25519 public keys.
    /// If present, the initiator may use one to enhance forward secrecy.
    /// For more information, see [`PublicKey`].
    pub otpk: Vec<PublicKey>,
}

impl PreKeyBundle {

    /// The total byte size of the pre-key bundle, which includes three Curve25519 public keys
    /// and one signature.
    /// This constant is used to verify the expected size of a `PreKeyBundle`.
    pub(crate) const BASE_SIZE: usize = CURVE25519_PUBLIC_LENGTH
        + CURVE25519_PUBLIC_LENGTH
        + CURVE25519_PUBLIC_LENGTH
        + SIGNATURE_LENGTH;

    /// Generates a new pre-key bundle.
    /// 
    /// This method does not generate one-time pre-keys.  
    /// For that functionality, see [`PreKeyBundle::new_with_otpk`].
    /// 
    /// # Arguments
    ///
    /// * `ik` - The recipient's identity key.
    /// * `spk` - The recipient's signed pre-key.
    ///
    /// # Returns
    ///
    /// * [`PreKeyBundle`] - A [`PreKeyBundle`] struct.
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

    /// Generates a new pre-key bundle,
    /// including one-time pre-keys.
    ///
    /// For a version that excludes one-time pre-keys, see [`PreKeyBundle::new`].
    /// 
    /// # Arguments
    ///
    /// * `ik` - The recipient's identity key.
    /// * `spk` - The recipient's signed pre-key.
    ///
    /// # Returns
    ///
    /// * [`PreKeyBundle`] - A [`PreKeyBundle`] struct.
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

    /// Adds a one-time pre-key
    ///
    /// # Arguments
    ///
    /// * `otpk` - The one-time pre-key to be added.
    pub fn add_otpk(&mut self, otpk: PublicKey) {
        self.otpk.push(otpk);
    }

    /// Calculates the size of the pre-key bundle.
    ///
    /// # Returns
    ///
    /// * `usize` - The number of elements in the pre-key bundle.
    pub fn size(&self) -> usize {
        CURVE25519_SECRET_LENGTH * 3 + SIGNATURE_LENGTH + self.otpk.len() * CURVE25519_PUBLIC_LENGTH
    }

    /// Converts each element of the pre-key bundle into bytes.
    ///
    /// # Returns
    ///
    /// * `Vec<u8>` - A vector containing the byte representation of each element in the pre-key bundle.
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

    /// Calculates the base64 of the pre-key bundle.
    ///
    /// # Returns
    ///
    /// * `String` - The base64-encoded string of the pre-key bundle.
    pub fn to_base64(self) -> String {
        general_purpose::STANDARD.encode(self.to_bytes())
    }
}

impl TryFrom<String> for PreKeyBundle {
    type Error = X3DHError;

    /// Converts a base64-encoded string into a [`PreKeyBundle`].
    ///
    /// # Returns
    ///
    /// * [`PreKeyBundle`] - The decoded pre-key bundle.
    ///
    /// # Errors
    ///
    /// * [`X3DHError::Base64DecodeError`] - Returned if `value` is not a valid Base64 string.
    /// * [`X3DHError::InvalidPreKeyBundle`] - Returned if the decoded byte vector does not match the expected size of [`PreKeyBundle::BASE_SIZE`].
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

/// A [`SessionKeys`] represents a set of cryptographic keys and associated metadata used during an active session.
#[derive(Clone)]
pub struct SessionKeys {
    /// The encryption key used for outgoing messages.
    /// For more information, see [`EncryptionKey`].
    ek: Option<EncryptionKey>,

    /// The decryption key used for incoming messages.
    /// For more information, see [`DecryptionKey`].
    dk: Option<DecryptionKey>,

    /// Optional associated data used for authentication and context binding.
    /// For more information, see [`AssociatedData`].
    aad: Option<AssociatedData>,
}

impl SessionKeys {

    /// Creates a new empty [`SessionKeys`] object
    ///
    /// This method does not init the session object.  
    /// For that functionality, see [`SessionKeys::new_with_keys`].
    /// 
    /// # Returns
    /// 
    /// * [`SessionKeys`] - An empty session object
    pub fn new() -> Self {
        Self {
            ek: None,
            dk: None,
            aad: None,
        }
    }

    /// Creates a [`SessionKeys`] object
    /// 
    /// For a version that does not init the session object, see [`SessionKeys::new`].
    /// 
    /// # Arguments
    ///
    /// * `ek` - The encryption key used in the session.
    /// * `dk` - The decryption key used in the session.
    /// * `aad` - Optional associated data containing identity information for both parties.
    ///
    /// # Returns
    ///
    /// * [`SessionKeys`] - A session object containing the provided keys and associated data.
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

    /// Returns the [`EncryptionKey`] for the current session, if available.
    ///
    /// # Returns
    ///
    /// * `Option<EncryptionKey>`  
    ///   * `Some(EncryptionKey)` - If the encryption key has been set.  
    ///   * `None` - If no encryption key is present.
    pub fn get_encryption_key(&self) -> Option<EncryptionKey> {
        self.ek.clone()
    }

    /// Returns the [`DecryptionKey`] for the current session, if available.
    ///
    /// # Returns
    ///
    /// * `Option<DecryptionKey>`  
    ///   * `Some(DecryptionKey)` - If the decryption key has been set.  
    ///   * `None` - If no decryption key is present.
    pub fn get_decryption_key(&self) -> Option<DecryptionKey> {
        self.dk.clone()
    }

    /// Returns the [`AssociatedData`] for the current session, if available.
    ///
    /// # Returns
    ///
    /// * `Option<AssociatedData>`  
    ///   * `Some(AssociatedData)` - If the associated data has been set.  
    ///   * `None` - If no associated data is present.
    pub fn get_associated_data(&self) -> Option<AssociatedData> {
        self.aad.clone()
    }

    /// Sets the [`EncryptionKey`] for the current session.
    ///
    /// # Arguments
    ///
    /// * `ek` - The encryption key to assign to the session.
    pub fn set_encryption_key(&mut self, ek: EncryptionKey) {
        self.ek = Some(ek);
    }

    /// Sets the [`DecryptionKey`] for the current session.
    ///
    /// # Arguments
    ///
    /// * `dk` - The decryption key to assign to the session.
    pub fn set_decryption_key(&mut self, dk: DecryptionKey) {
        self.dk = Some(dk);
    }

    /// Sets the [`AssociatedData`] for the current session.
    ///
    /// # Arguments
    ///
    /// * `aad` - The associated data to assign to the session.
    pub fn set_associated_data(&mut self, aad: AssociatedData) {
        self.aad = Some(aad);
    }

}

/// A 256-bit secret shared between two parties after performing a key agreement (in this case, Diffie-Hellman).
#[derive(Clone, Zeroize, ZeroizeOnDrop, Debug)]
pub struct SharedSecret([u8; AES256_SECRET_LENGTH]);

impl From<(EncryptionKey, DecryptionKey)> for SharedSecret {

    /// Derives a [`SharedSecret`] from an [`EncryptionKey`] and a [`DecryptionKey`].
    /// 
    /// # Arguments
    /// 
    /// * `ek` - The encryption key.
    /// * `dk` - The decryption key.
    /// 
    /// # Returns
    /// 
    /// * [`SharedSecret`] - The derived shared secret.
    fn from((ek, dk): (EncryptionKey, DecryptionKey)) -> SharedSecret {
        let mut vec = ek.as_ref().to_vec();
        vec.extend_from_slice(dk.as_ref());
        SharedSecret(*array_ref!(vec, 0, AES256_SECRET_LENGTH))
    }
}

impl From<(DecryptionKey, EncryptionKey)> for SharedSecret {

    /// Derives a [`SharedSecret`] from a [`DecryptionKey`] and an [`EncryptionKey`].
    /// 
    /// # Arguments
    /// 
    /// * `dk` - The decryption key.
    /// * `ek` - The encryption key.
    /// 
    /// # Returns
    /// 
    /// * [`SharedSecret`] - The derived shared secret.
    fn from((dk, ek): (DecryptionKey, EncryptionKey)) -> SharedSecret {
        let mut vec = dk.as_ref().to_vec();
        vec.extend_from_slice(ek.as_ref());
        SharedSecret(*array_ref!(vec, 0, AES256_SECRET_LENGTH))
    }
}

impl AsRef<[u8; AES256_SECRET_LENGTH]> for SharedSecret {

    /// Returns a shared reference to the current [`SharedSecret`].
    /// 
    /// # Returns
    /// 
    /// * [`&SharedSecret`] - The shared reference.
    fn as_ref(&self) -> &[u8; AES256_SECRET_LENGTH] {
        &self.0
    }
}

impl From<[u8; AES256_SECRET_LENGTH]> for SharedSecret {

    /// Derives a [`SharedSecret`] from a `[u8; `[AES256_SECRET_LENGTH]`]`.
    /// 
    /// # Arguments
    /// 
    /// * `value` - The vector.
    /// 
    /// # Returns
    /// 
    /// * [`SharedSecret`] - The derived shared secret.
    fn from(value: [u8; AES256_SECRET_LENGTH]) -> SharedSecret {
        SharedSecret(value)
    }
}

/// A public key used to verify signatures in the X3DH protocol.
#[derive(Clone, Debug)]
pub struct VerifyingKey(pub [u8; CURVE25519_PUBLIC_LENGTH]);

impl From<SigningKey> for VerifyingKey {

    /// Derives a [`VerifyingKey`] from a [`SigningKey`].
    ///
    /// # Arguments
    ///
    /// * `private_key` - The private key from which the verifying key is derived.
    ///
    /// # Returns
    ///
    /// * [`VerifyingKey`] - The derived verifying key.
    fn from(private_key: SigningKey) -> VerifyingKey {
        let dalek_private_key = ed25519_dalek::SigningKey::from(private_key.0);
        let dalek_public_key = ed25519_dalek::VerifyingKey::from(&dalek_private_key);
        VerifyingKey(dalek_public_key.to_bytes())
    }
}

impl From<&SigningKey> for VerifyingKey {

    /// Derives a [`VerifyingKey`] from a shared reference to a [`SigningKey`].
    ///
    /// # Arguments
    ///
    /// * `private_key` - The shared reference to the private key from which the verifying key is derived.
    ///
    /// # Returns
    ///
    /// * [`VerifyingKey`] - The derived verifying key.
    fn from(private_key: &SigningKey) -> VerifyingKey {
        let dalek_private_key = ed25519_dalek::SigningKey::from(private_key.0);
        let dalek_public_key = ed25519_dalek::VerifyingKey::from(&dalek_private_key);
        VerifyingKey(dalek_public_key.to_bytes())
    }
}

impl From<PublicKey> for VerifyingKey {

    /// Derives a [`VerifyingKey`] from a [`PublicKey`].
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key from which the verifying key is derived.
    ///
    /// # Returns
    ///
    /// * [`VerifyingKey`] - The derived verifying key.
    fn from(public_key: PublicKey) -> VerifyingKey {
        VerifyingKey(public_key.0)
    }
}

impl From<&PublicKey> for VerifyingKey {

    /// Derives a [`VerifyingKey`] from a shared reference to a [`PublicKey`].
    ///
    /// # Arguments
    ///
    /// * `public_key` - The shared reference to the public key from which the verifying key is derived.
    ///
    /// # Returns
    ///
    /// * [`VerifyingKey`] - The derived verifying key.
    fn from(public_key: &PublicKey) -> VerifyingKey {
        VerifyingKey(public_key.0)
    }
}

impl AsRef<[u8; CURVE25519_PUBLIC_LENGTH]> for VerifyingKey {

    /// Returns a shared reference to this [`VerifyingKey`].
    /// 
    /// # Returns
    /// 
    /// * [`&VerifyingKey`] - The shared reference.
    fn as_ref(&self) -> &[u8; CURVE25519_PUBLIC_LENGTH] {
        &self.0
    }
}

impl VerifyingKey {

    /// Verifies that a given [`Signature`] is valid for a message using the current [`VerifyingKey`].
    ///
    /// # Arguments
    ///
    /// * `signature` - The signature to be verified.
    /// * `message` - The original message that was supposedly signed.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the signature is valid.
    /// 
    /// # Errors
    /// 
    /// * [`ed25519_dalek::SignatureError`] - Returned if the signature is invalid or the key is malformed.
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

/// An Ed25519 signing key used to create digital signatures in the X3DH protocol.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct SigningKey([u8; CURVE25519_PUBLIC_LENGTH]);

impl SigningKey {

    /// Generates a new random [`SigningKey`] using a secure random number generator.
    /// This function uses a cryptographically secure RNG via [`OsRng`] to ensure key unpredictability.
    /// 
    /// # Returns
    ///
    /// * [`SigningKey`] - A newly generated signing key based on the Ed25519 curve.
    pub(crate) fn new() -> SigningKey {
        let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        SigningKey(key.to_bytes())
    }

    /// Signs a message using the current [`SigningKey`].
    ///
    /// # Arguments
    ///
    /// * `message` - A byte slice representing the message to be signed.
    ///
    /// # Returns
    ///
    /// * [`Signature`] - The Ed25519 signature of the message.
    pub(crate) fn sign(&self, message: &[u8]) -> Signature {
        let mut dalek_private_key = ed25519_dalek::SigningKey::from(self.0);
        let signature = dalek_private_key.sign(message);
        Signature(signature.to_bytes())
    }

    /// Computes a Diffie-Hellman shared secret using the current private key and a public key.
    /// This function uses the X25519 elliptic curve Diffie-Hellman key exchange algorithm
    /// via the [`x25519_dalek`] crate to securely derive a shared secret.
    /// 
    /// # Arguments
    ///
    /// * `public_key` - A reference to the public key of the other party.
    ///
    /// # Returns
    ///
    /// * [`SharedSecret`] - The resulting shared secret derived from the key exchange.
    pub(crate) fn diffie_hellman(&self, public_key: &PublicKey) -> SharedSecret {
        let dalek_private_key = StaticSecret::from(self.0);
        let dalek_public_key = x25519_dalek::PublicKey::from(public_key.0);
        let shared_secret = dalek_private_key.diffie_hellman(&dalek_public_key);
        SharedSecret(shared_secret.to_bytes())
    }
}

impl From<PrivateKey> for SigningKey {

    /// Derives a [`SigningKey`] from a [`PrivateKey`].
    ///
    /// # Arguments
    ///
    /// * `private_key` - The private key from which the signing key is derived.
    ///
    /// # Returns
    ///
    /// * [`SigningKey`] - The derived verifying key.
    fn from(private_key: PrivateKey) -> SigningKey {
        SigningKey(private_key.0)
    }
}

impl From<&PrivateKey> for SigningKey {

    /// Derives a [`SigningKey`] from a shared reference to a [`PrivateKey`].
    ///
    /// # Arguments
    ///
    /// * `private_key` - The shared reference to the private key from which the signing key is derived.
    ///
    /// # Returns
    ///
    /// * [`SigningKey`] - The derived verifying key.
    fn from(private_key: &PrivateKey) -> SigningKey {
        SigningKey(private_key.0)
    }
}

/// A key pair used as a signed pre-key in the X3DH protocol.
#[derive(Clone)]
pub(crate) struct SignedPreKey {

    /// The private component of the signed pre-key, used for key agreement.
    pub(crate) private_key: PrivateKey,

    /// The public component of the signed pre-key, shared with other parties.
    pub(crate) public_key: PublicKey,
}

impl SignedPreKey {

    /// Generates a new [`SignedPreKey`] key pair.
    /// This function creates a new Curve25519 private key and derives the corresponding public key,
    /// forming a complete signed pre-key pair used in the X3DH protocol.
    ///
    /// # Returns
    ///
    /// * [`SignedPreKey`] - A newly generated key pair containing both private and public keys.
    pub(crate) fn new() -> SignedPreKey {
        let private_key = PrivateKey::new();
        let public_key = PublicKey::from(&private_key);
        SignedPreKey {
            private_key,
            public_key,
        }
    }
}

/// A Curve25519 private key used in the X3DH key exchange for computing shared secrets.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey([u8; CURVE25519_SECRET_LENGTH]);

impl PrivateKey {

    /// Generates a new Curve25519 private key.
    /// This function uses a cryptographically secure random number generator to produce
    /// a new X25519 `StaticSecret`, returning it as a [`PrivateKey`] for use in key exchanges.
    ///
    /// # Returns
    ///
    /// * [`PrivateKey`] - A randomly generated Curve25519 private key.
    pub fn new() -> PrivateKey {
        let key = StaticSecret::random_from_rng(&mut OsRng);
        PrivateKey(key.to_bytes())
    }

    /// Performs a Diffie-Hellman key exchange with a given public key.
    /// This function computes the shared secret between this private key and a peer’s [`PublicKey`],
    /// returning the resulting [`SharedSecret`] as a byte array.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key of the other party involved in the key exchange.
    ///
    /// # Returns
    ///
    /// * [`SharedSecret`] - The derived shared secret.
    pub(crate) fn diffie_hellman(&self, public_key: &PublicKey) -> SharedSecret {
        let dalek_private_key = StaticSecret::from(self.0);
        let dalek_public_key = x25519_dalek::PublicKey::from(public_key.0);
        let shared_secret = dalek_private_key.diffie_hellman(&dalek_public_key);
        SharedSecret(shared_secret.to_bytes())
    }

    /// Converts the current [`PrivateKey`] into bytes.
    ///
    /// # Returns
    ///
    /// * `Vec<u8>` - A vector of bytes derived from the current [`PrivateKey`].
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Converts the current [`PrivateKey`] into a base64-encoded string.
    ///
    /// # Returns
    ///
    /// * `String` - The base64-encoded string of the current [`PrivateKey`].
    pub fn to_base64(&self) -> String {
        general_purpose::STANDARD.encode(self.to_bytes())
    }

    /// Converts a base64-encoded string into a [`PrivateKey`].
    ///
    /// # Arguments
    /// 
    /// * `value` - The base64-encoded string to be converted.
    /// 
    /// # Returns
    ///
    /// * [`PrivateKey`] - The decoded private key.
    ///
    /// # Errors
    ///
    /// * [`X3DHError::Base64DecodeError`] - Returned if `value` is not a valid Base64 string.
    /// * [`X3DHError::InvalidPrivateKey`] - Returned if the decoded byte vector does not match the expected size of [`CURVE25519_SECRET_LENGTH`].
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

    /// Returns a shared reference to the current [`PrivateKey`].
    /// 
    /// # Returns
    /// 
    /// * `&[u8; CURVE25519_SECRET_LENGTH]` - The shared reference.
    fn as_ref(&self) -> &[u8; CURVE25519_SECRET_LENGTH] {
        &self.0
    }
}

impl From<SigningKey> for PrivateKey {

    /// Derives a [`PrivateKey`] from a [`SigningKey`].
    /// 
    /// # Arguments
    /// 
    /// * `private_key` - The signing key to be converted.
    /// 
    /// # Returns
    /// 
    /// * [`PrivateKey`] - The derived private key.
    fn from(private_key: SigningKey) -> PrivateKey {
        let dalek_private_key = StaticSecret::from(private_key.0);
        PrivateKey(dalek_private_key.to_bytes())
    }
}

impl From<&SigningKey> for PrivateKey {

    /// Derives a [`PrivateKey`] from a shared reference to a [`SigningKey`].
    /// 
    /// # Arguments
    /// 
    /// * `private_key` - The reference of the signing key to be converted.
    /// 
    /// # Returns
    /// 
    /// * [`PrivateKey`] - The derived private key.
    fn from(private_key: &SigningKey) -> PrivateKey {
        let dalek_private_key = StaticSecret::from(private_key.0);
        PrivateKey(dalek_private_key.to_bytes())
    }
}

/// A Curve25519 public key used in the X3DH protocol to represent identity, ephemeral, and pre-keys.
/// This type can be derived from private or signing keys and is hashable and comparable.
#[derive(Clone, Debug, Eq, Hash)]
pub struct PublicKey(pub [u8; CURVE25519_PUBLIC_LENGTH]);

impl From<PrivateKey> for PublicKey {

    /// Derives a [`PublicKey`] from a [`PrivateKey`].
    /// 
    /// # Arguments
    /// 
    /// * `private_key` - The private key to be converted.
    /// 
    /// # Returns
    /// 
    /// * [`PublicKey`] - The derived public key.
    fn from(private_key: PrivateKey) -> PublicKey {
        let dalek_private_key = x25519_dalek::StaticSecret::from(private_key.0);
        let dalek_public_key = x25519_dalek::PublicKey::from(&dalek_private_key);
        PublicKey(dalek_public_key.to_bytes())
    }
}

impl From<&PrivateKey> for PublicKey {

    /// Derives a [`PublicKey`] from a shared reference to a [`PrivateKey`].
    /// 
    /// # Arguments
    /// 
    /// * `private_key` - The shared reference to the private key to be converted.
    /// 
    /// # Returns
    /// 
    /// * [`PublicKey`] - The derived public key.
    fn from(private_key: &PrivateKey) -> PublicKey {
        let dalek_private_key = x25519_dalek::StaticSecret::from(private_key.0);
        let dalek_public_key = x25519_dalek::PublicKey::from(&dalek_private_key);
        PublicKey(dalek_public_key.to_bytes())
    }
}

impl From<VerifyingKey> for PublicKey {

    /// Derives a [`PublicKey`] from a [`VerifyingKey`].
    /// 
    /// # Arguments
    /// 
    /// * `public_key` - The veryfing key to be converted.
    /// 
    /// # Returns
    /// 
    /// * [`PublicKey`] - The derived public key.
    fn from(public_key: VerifyingKey) -> PublicKey {
        PublicKey(public_key.0)
    }
}

impl From<&VerifyingKey> for PublicKey {

    /// Derives a [`PublicKey`] from a shared reference to a [`VerifyingKey`].
    /// 
    /// # Arguments
    /// 
    /// * `public_key` - The shared reference to the veryfing key to be converted.
    /// 
    /// # Returns
    /// 
    /// * [`PublicKey`] - The derived public key.
    fn from(public_key: &VerifyingKey) -> PublicKey {
        PublicKey(public_key.0)
    }
}

impl From<SigningKey> for PublicKey {

    /// Derives a [`PublicKey`] from a [`SigningKey`].
    /// 
    /// # Arguments
    /// 
    /// * `value` - The signing key to be converted.
    /// 
    /// # Returns
    /// 
    /// * [`PublicKey`] - The derived public key.
    fn from(value: SigningKey) -> Self {
        let key = VerifyingKey::from(&value);
        PublicKey::from(key)
    }
}

impl From<&SigningKey> for PublicKey {

    /// Derives a [`PublicKey`] from a shared reference to a [`SigningKey`].
    /// 
    /// # Arguments
    /// 
    /// * `value` - The shared reference to the signing key to be converted.
    /// 
    /// # Returns
    /// 
    /// * [`PublicKey`] - The derived public key.
    fn from(value: &SigningKey) -> Self {
        let key = VerifyingKey::from(value);
        PublicKey::from(key)
    }
}

impl From<&[u8; CURVE25519_PUBLIC_LENGTH]> for PublicKey {

    /// Derives a [`PublicKey`] from a shared reference to a `[u8; `[CURVE25519_PUBLIC_LENGTH]`]`.
    /// 
    /// # Arguments
    /// 
    /// * `value` - The shared reference.
    /// 
    /// # Returns
    /// 
    /// * [`PublicKey`] - The derived public key.
    fn from(value: &[u8; CURVE25519_PUBLIC_LENGTH]) -> PublicKey {
        PublicKey(value.clone())
    }

}

impl AsRef<[u8; CURVE25519_PUBLIC_LENGTH]> for PublicKey {

    /// Returns a shared reference to the current [`PublicKey`].
    /// 
    /// # Returns
    /// 
    /// * `&[u8; CURVE25519_PUBLIC_LENGTH]` - The shared reference.
    fn as_ref(&self) -> &[u8; CURVE25519_PUBLIC_LENGTH] {
        &self.0
    }
}

impl PartialEq for PublicKey {

    /// Compares two [`PublicKey`] instances for equality.
    ///
    /// # Arguments
    ///
    /// * `other` - The other [`PublicKey`] to compare against.
    ///
    /// # Returns
    ///
    /// * `bool` - `true` if the underlying byte representations of both keys are equal, otherwise `false`.
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl PublicKey {

    /// Returns the SHA-256 hash of the current [`PublicKey`].
    ///
    /// # Returns
    ///
    /// * [`Sha256Hash`] - The SHA-256 digest of the public key.
    pub fn hash(&self) -> Sha256Hash {
        let digest = Sha256::digest(self.0.as_ref());
        Sha256Hash(*array_ref![digest, 0, SHA256_HASH_LENGTH])
    }

    /// Converts the current [`PublicKey`] into a base64-encoded string.
    ///
    /// # Returns
    ///
    /// * `String` - The base64-encoded string of the current [`PublicKey`].
    pub fn to_base64(&self) -> String {
        general_purpose::STANDARD.encode(self.0.to_vec())
    }

    /// Converts a base64-encoded string into a [`PublicKey`].
    ///
    /// # Arguments
    /// 
    /// * `value` - The base64-encoded string to be converted.
    /// 
    /// # Returns
    ///
    /// * `PublicKey` - The decoded public key.
    ///
    /// # Errors
    ///
    /// * [`X3DHError::Base64DecodeError`] - Returned if `value` is not a valid Base64 string.
    /// * [`X3DHError::InvalidPublicKey`] - Returned if the decoded byte vector does not match the expected size of [`CURVE25519_PUBLIC_LENGTH`].
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

/// A digital signature used to authenticate public keys within the X3DH protocol.
#[derive(Clone, Debug)]
pub struct Signature(pub [u8; SIGNATURE_LENGTH]);

impl AsRef<[u8; SIGNATURE_LENGTH]> for Signature {

    /// Returns a shared reference to the current [`Signature`].
    /// 
    /// # Returns
    /// 
    /// * `&[u8; SIGNATURE_LENGTH]` - The shared reference.
    fn as_ref(&self) -> &[u8; SIGNATURE_LENGTH] {
        &self.0
    }
}

impl From<[u8; SIGNATURE_LENGTH]> for Signature {

    /// Derives a [`Signature`] from a `[u8; `[SIGNATURE_LENGTH]`]`.
    /// 
    /// # Arguments
    /// 
    /// * `value` - A byte array representing the raw signature data.
    /// 
    /// # Returns
    /// 
    /// * [`Signature`] - The derived signature.
    fn from(value: [u8; SIGNATURE_LENGTH]) -> Signature {
        Signature(value)
    }
}

/// Additional data exchanged during the X3DH handshake, containing both parties' identity keys.
#[derive(Clone, Debug)]
pub struct AssociatedData {
    /// The identity public key of the initiator.
    pub(crate) initiator_identity_key: PublicKey,

    /// The identity public key of the responder.
    pub(crate) responder_identity_key: PublicKey,
}


impl AssociatedData {

    /// Total size in bytes of the associated data, which is the sum of the two public key lengths
    pub const SIZE: usize = CURVE25519_PUBLIC_LENGTH + CURVE25519_PUBLIC_LENGTH;

    /// Converts the current [`AssociatedData`] into bytes.
    ///
    /// # Returns
    ///
    /// * `Vec<u8>` - A vector of bytes derived from the current [`AssociatedData`].
    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.initiator_identity_key.0.as_ref());
        out.extend_from_slice(self.responder_identity_key.0.as_ref());
        out
    }

    /// Creates a new [`AssociatedData`] instance from two public keys.
    ///
    /// # Arguments
    ///
    /// * `ik` - The identity public key of the initiator.
    /// * `spk` - The identity public key of the responder.
    ///
    /// # Returns
    ///
    /// * [`AssociatedData`] - A new instance containing both public keys.
    pub fn new(ik: PublicKey, spk: PublicKey) -> Self {
        Self {
            initiator_identity_key: ik,
            responder_identity_key: spk,
        }
    }
}

impl TryFrom<&[u8; Self::SIZE]> for AssociatedData {
    type Error = X3DHError;

    /// Attempts to create an [`AssociatedData`] instance from a byte slice of length [`Self::SIZE`].
    ///
    /// # Arguments
    ///
    /// * `value` - A reference to a byte array of length [`Self::SIZE`] representing two concatenated public keys.
    ///
    /// # Returns
    ///
    /// * `Ok(AssociatedData)` - If the conversion is successful.
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

/// A SHA-256 hash used for identifying and verifying keys or values in the X3DH protocol.
#[derive(Clone, Eq, Debug)]
pub struct Sha256Hash(pub [u8; SHA256_HASH_LENGTH]);

impl From<&[u8; SHA256_HASH_LENGTH]> for Sha256Hash {

    /// Derives a [`Sha256Hash`] from a shared reference to a `[u8; `[SHA256_HASH_LENGTH]`]`.
    ///
    /// # Arguments
    ///
    /// * `value` - The shared reference.
    ///
    /// # Returns
    ///
    /// * [`Sha256Hash`] - The derived sha-256 hash.
    fn from(value: &[u8; SHA256_HASH_LENGTH]) -> Sha256Hash {
        Sha256Hash(*value)
    }
}

impl Hash for Sha256Hash {

    /// Feeds the internal byte array into the given hasher.
    /// This allows [`Sha256Hash`] to be used in hash maps or sets.
    ///
    /// # Arguments
    ///
    /// * `state` - The hasher state to update.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialEq for Sha256Hash {

    /// Compares two [`Sha256Hash`] values for equality based on their byte content.
    ///
    /// # Arguments
    ///
    /// * `other` - The other [`Sha256Hash`] to compare with.
    ///
    /// # Returns
    ///
    /// * `true` if the internal byte arrays are equal, otherwise `false`.
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// A fixed-length random challenge used for proving possession of a key during authentication.
#[derive(Clone, Debug)]
pub struct Challenge(pub(crate) [u8; CHALLENGE_LENGTH]);

impl From<&[u8; CHALLENGE_LENGTH]> for Challenge {

    /// Derives a [`Challenge`] from a shared reference to a `[u8; CHALLENGE_LENGTH]` array.
    ///
    /// # Arguments
    ///
    /// * `value` - A reference to a byte array of length [`CHALLENGE_LENGTH`].
    ///
    /// # Returns
    ///
    /// * [`Challenge`] - The derived challenge.
    fn from(value: &[u8; CHALLENGE_LENGTH]) -> Challenge {
        Challenge(*value)
    }
}

impl TryFrom<&[u8]> for Challenge {
    type Error = X3DHError;

    /// Derives a [`Challenge`] from a shared reference to a `[u8; CHALLENGE_LENGTH]` array.
    ///
    /// # Arguments
    ///
    /// * `value` - A reference to a byte array of length [`CHALLENGE_LENGTH`].
    ///
    /// # Returns
    ///
    /// * [`Challenge`] - The derived challenge.
    /// 
    /// # Errors
    /// 
    /// * [`X3DHError::InvalidChallenge`] - Returned if `value` does not match the expected size of [`CHALLENGE_LENGTH`].
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != CHALLENGE_LENGTH {
            return Err(X3DHError::InvalidChallenge)
        }
        let data = *array_ref!(value, 0, CHALLENGE_LENGTH);
        Ok(Challenge(data))
    }
}

/// A message sent by the initiator in the X3DH key exchange protocol.
#[derive(Clone)]
pub struct InitialMessage {
    /// The initiator’s identity public key.
    pub identity_key: PublicKey,

    /// The initiator’s ephemeral public key.
    pub ephemeral_key: PublicKey,

    /// The SHA-256 hash of the responder’s signed pre-key.
    pub prekey_hash: Sha256Hash,

    /// Optional SHA-256 hash of the responder’s one-time pre-key.
    pub one_time_key_hash: Option<Sha256Hash>,

    /// A challenge generated by the initiator for authentication.
    pub challenge: Challenge,

    /// Associated identity key data for both parties.
    pub associated_data: AssociatedData,
}

impl InitialMessage {
    
    /// The base byte size without an optional one-time prekey hash.
    pub(crate) const BASE_SIZE: usize = CURVE25519_PUBLIC_LENGTH
        + CURVE25519_PUBLIC_LENGTH
        + SHA256_HASH_LENGTH
        + CHALLENGE_LENGTH
        + CURVE25519_PUBLIC_LENGTH
        + CURVE25519_PUBLIC_LENGTH;

    /// The total byte size of the message when the one-time prekey hash is included.
    pub(crate) const SIZE_WITH_OTPK: usize = Self::BASE_SIZE + SHA256_HASH_LENGTH;

    /// Returns a clone of the [`AssociatedData`] from the current message.
    ///
    /// # Returns
    ///
    /// * [`AssociatedData`] - The associated data contained in the message.
    pub fn get_associated_data(&self) -> AssociatedData {
        self.associated_data.clone()
    }

    /// Converts the current [`InitialMessage`] into bytes.
    ///
    /// # Returns
    ///
    /// * `Vec<u8>` - A vector of bytes derived from the current [`InitialMessage`].
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

    /// Converts the current [`InitialMessage`] into a base64-encoded string.
    ///
    /// # Returns
    ///
    /// * `String` - The base64-encoded string of the current [`InitialMessage`].
    pub fn to_base64(self) -> String {
        general_purpose::STANDARD.encode(self.to_bytes())
    }

    /// Calculates the size of the current [`InitialMessage`].
    ///
    /// # Returns
    ///
    /// * `usize` - The size of the current [`InitialMessage`]:
    ///     * [`Self::BASE_SIZE`] - If there is no one-time prekey hash.
    ///     * [`Self::SIZE_WITH_OTPK`] - If there is a one-time prekey hash.
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

    /// Derives a [`InitialMessage`] from base64-encoded string.
    ///
    /// # Arguments
    ///
    /// * `value` - A base64-encoded string.
    ///
    /// # Returns
    ///
    /// * [`InitialMessage`] - The derived initial message.
    /// 
    /// # Errors
    /// 
    /// * [`X3DHError::Base64DecodeError`] - Returned if `value` is not a valid Base64 string.
    /// * [`X3DHError::InvalidInitialMessage`] - Returned if the decoded byte vector does not match the expected size of [`Self::BASE_SIZE`] or [`Self::SIZE_WITH_OTPK`].
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



/// A 256-bit AES key used for encrypting messages in the X3DH session.
#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct EncryptionKey([u8; AES256_SECRET_LENGTH]);

impl EncryptionKey {

    /// Encrypts the given `data` using AES-256-GCM with the given additional authenticated data (AAD).
    /// The output format is: `[nonce | aad | ciphertext]`, all base64-encoded.
    /// 
    /// # Arguments
    ///
    /// * `data`: The plaintext data to be encrypted.
    /// * `aad`: Additional data to authenticate but not encrypt.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The base64-encoded ciphertext, nonce, and AAD.
    /// 
    /// # Errors
    /// 
    /// * [`X3DHError::AesGcmInvalidLength`] - Returned if AES-GCM decryption fails due to an unexpected ciphertext length.
    pub fn encrypt(&self, data: &[u8], aad: &[u8]) -> Result<String, X3DHError> {
        let nonce = &Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes256Gcm::new_from_slice(&self.0);
        let payload = Payload {
            aad: &aad.clone(),
            msg: data,
        };
        let encrypt_msg = cipher?.encrypt(nonce, payload)?;
        let mut output = vec![];
        output.extend_from_slice(&nonce.to_vec());
        output.extend_from_slice(&aad.clone());
        output.extend_from_slice(&encrypt_msg);
        let b64 = general_purpose::STANDARD.encode(output);

        Ok(b64)
    }

    /// Encrypts a short `data` slice deterministically to form a `Challenge`.
    /// This uses a fixed nonce (`"hello world!"`).
    ///
    /// # Arguments
    ///
    /// * `data` - The plaintext data to encrypt into a challenge.
    ///
    /// # Returns
    ///
    /// * `Ok([Challenge])` - The encrypted data as a fixed-size challenge.
    /// 
    /// # Errors
    /// 
    /// * [`X3DHError::AesGcmInvalidLength`] - Returned if AES-GCM decryption fails due to an unexpected ciphertext length.
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

    /// Derives an [`EncryptionKey`] from a [`SharedSecret`].
    ///
    /// # Arguments
    ///
    /// * `value` - A shared secret.
    ///
    /// # Returns
    ///
    /// * [`EncryptionKey`] - The derived encryption key.
    fn from(value: SharedSecret) -> EncryptionKey {
        EncryptionKey(value.0)
    }
}

impl AsRef<[u8; AES256_SECRET_LENGTH]> for EncryptionKey {

    /// Returns a shared reference to the current [`EncryptionKey`].
    /// 
    /// # Returns
    /// 
    /// * `&[u8; AES256_SECRET_LENGTH]` - The shared reference.
    fn as_ref(&self) -> &[u8; AES256_SECRET_LENGTH] {
        &self.0
    }
}

/// A 256-bit AES key used for decrypting messages in the X3DH session.
#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct DecryptionKey([u8; AES256_SECRET_LENGTH]);

impl DecryptionKey {

    /// Decrypts AES-GCM encrypted `data` using the provided `nonce` and additional authenticated data (AAD).
    ///
    /// # Arguments
    ///
    /// * `data` - The encrypted ciphertext.
    /// * `nonce` - The nonce used during encryption (must be the same as used to encrypt).
    /// * `aad` - The additional authenticated data that was passed to the encrypting function.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The decrypted plaintext if decryption is successful.
    /// 
    /// # Errors
    /// 
    /// * [`X3DHError::AesGcmInvalidLength`] - Returned if AES-GCM decryption fails due to an unexpected ciphertext length.
    pub fn decrypt(
        &self,
        data: &[u8],
        nonce: &[u8; AES256_NONCE_LENGTH],
        aad: &[u8],
    ) -> Result<Vec<u8>, X3DHError> {
        let cipher = Aes256Gcm::new_from_slice(&self.0);
        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            aad: &aad.clone(),
            msg: data,
        };
        let output = cipher?.decrypt(nonce, payload)?;
        Ok(output)
    }

    /// Decrypts a [`Challenge`] value using a fixed nonce.
    /// This is the inverse of `EncryptionKey::encrypt_challenge` and is only valid if
    /// the challenge was encrypted with the same key and the static nonce `"hello world!"`.
    ///
    /// # Arguments
    ///
    /// * `data` - A challenge containing the encrypted data.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The decrypted bytes if successful.
    /// 
    /// # Errors
    /// 
    /// * [`X3DHError::AesGcmInvalidLength`] - Returned if AES-GCM decryption fails due to an unexpected ciphertext length.
    pub(crate) fn decrypt_challenge(&self, data: &Challenge) -> Result<Vec<u8>, X3DHError> {
        let nonce = b"hello world!";
        let nonce = Nonce::from_slice(nonce);
        let cipher = Aes256Gcm::new_from_slice(&self.0);
        let output = cipher?.decrypt(nonce, data.0.as_ref())?;
        Ok(output)
    }
}

impl From<SharedSecret> for DecryptionKey {

    /// Derives an [`DecryptionKey`] from a [`SharedSecret`].
    ///
    /// # Arguments
    ///
    /// * `value` - A shared secret.
    ///
    /// # Returns
    ///
    /// * [`DecryptionKey`] - The derived decryption key.
    fn from(value: SharedSecret) -> DecryptionKey {
        DecryptionKey(value.0)
    }
}

impl AsRef<[u8; AES256_SECRET_LENGTH]> for DecryptionKey {

    /// Returns a shared reference to the current [`DecryptionKey`].
    /// 
    /// # Returns
    /// 
    /// * `&[u8; AES256_SECRET_LENGTH]` - The shared reference.
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
