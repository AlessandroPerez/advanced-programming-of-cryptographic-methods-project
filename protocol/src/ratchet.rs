//! This module implements the Double Ratchet algorithm, a core component for secure, asynchronous messaging.
//! The Double Ratchet ensures forward secrecy and post-compromise security by combining symmetric-key and Diffie-Hellman ratcheting.
//! It manages the cryptographic state for sending and receiving messages, handling key derivation, message encryption,
//! and decryption, including mechanisms for skipping and reordering messages.
//! For more information, see the [Signal Protocol specification](https://signal.org/docs/specifications/doubleratchet/).

use std::cmp::PartialEq;
use std::collections::HashMap;
use std::fmt::Debug;
use aes_gcm::aead::Buffer;
use arrayref::array_ref;
use base64::Engine;
use base64::engine::general_purpose;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::utils::{AssociatedData, DecryptionKey, EncryptionKey, PrivateKey, PublicKey, SharedSecret};
use hkdf::Hkdf;
use sha2::Sha256;
use crate::constants::{AES256_NONCE_LENGTH, AES256_SECRET_LENGTH, CURVE25519_PUBLIC_LENGTH, MAX_SKIPS};
use crate::errors::RatchetError;
use crate::errors::RatchetError::ConversionError;

/// A [`RatchetKeyPair`] consists of a public and private key, 
/// used in the Diffie-Hellman ratchet process to generate new key pairs and perform key exchanges.
#[derive(Clone)]
pub struct RatchetKeyPair {
    /// The public key component of the key pair.
    /// For more information, see [`PublicKey`].
    public_key: PublicKey,

    /// The private key component of the key pair.
    /// For more information, see [`PrivateKey`].
    private_key: PrivateKey,
}

impl RatchetKeyPair {
    /// Generates a new [`RatchetKeyPair`] with a freshly created private key
    /// and its corresponding public key.
    ///
    /// If you want to create a [`RatchetKeyPair`] from an existing [`PrivateKey`] and [`PublicKey`],
    /// see [`RatchetKeyPair::new_from`]
    /// 
    /// # Returns
    /// 
    /// * [`RatchetKeyPair`] - A [`RatchetKeyPair`] struct.
    pub fn new() -> Self {
        let private_key = PrivateKey::new();
        let public_key = PublicKey::from(&private_key);
        Self {
            public_key,
            private_key,
        }
    }

    /// Constructs a [`RatchetKeyPair`] from an existing private and public key.
    ///
    /// If you want to create a [`RatchetKeyPair`] without a [`PrivateKey`] and a [`PublicKey`],
    /// see [`RatchetKeyPair::new`]
    /// 
    /// # Arguments
    /// 
    /// * `private_key` - The private key.
    /// * `public_key` - The public key associated with the private key.
    /// 
    /// # Returns
    /// 
    /// * [`RatchetKeyPair`] - A [`RatchetKeyPair`] struct.
    pub fn new_from(private_key: PrivateKey, public_key: PublicKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    /// Performs a Diffie-Hellman key exchange with the provided public key.
    /// This is used in the ratchet process to derive new shared secrets.
    /// 
    /// # Arguments
    /// 
    /// * `other_public_key` - The public key of the other party involved in the key exchange.
    /// 
    /// # Returns
    /// 
    /// * [`SharedSecret`] - A [`SharedSecret`] derived from this key pair's private key and the given public key.
    fn diffie_hellman(
        &self,
        other_public_key: &PublicKey,
    ) -> SharedSecret {
        self.private_key.diffie_hellman(other_public_key)
    }
}

/// A [`Header`] represents a Double Ratchet header containing key and message state metadata for the encrypted message.
#[derive(Clone)]
struct Header {

    /// The sender's current Diffie-Hellman public key.
    /// For more information, see [`PublicKey`].
    dhs: PublicKey,

    /// The previous chain length, indicating how many messages were sent under the previous sending chain.
    pn: u64,

    /// The current message number in the sending chain.
    ns: u64,
}

impl Header {

    /// The total byte length of the serialized [`Header`], which includes:
    /// * the length of the public key ([`AES256_SECRET_LENGTH`])
    /// * two `u64` values (`pn` and `ns`)
    const LENGTH: usize = AES256_SECRET_LENGTH + size_of::<u64>() * 2;

    /// Constructs a new [`Header`] with the given public key and message counters.
    ///
    /// # Arguments
    ///
    /// * `dhs` – The sender's current Diffie-Hellman public key.
    /// * `pn` – The number of messages sent in the previous sending chain (previous message number).
    /// * `ns` – The message number in the current sending chain.
    ///
    /// # Returns
    ///
    /// * [`Header`] - A new [`Header`] instance containing the provided values.
    pub fn new(dhs: PublicKey, pn: u64, ns: u64) -> Self {
        Self { dhs, pn, ns }
    }

    /// Converts each element of the [`Header`] into bytes.
    ///
    /// # Returns
    ///
    /// * `Vec<u8>` - A vector containing the byte representation of each element in the [`Header`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.dhs.as_ref());
        bytes.extend_from_slice(&self.pn.to_le_bytes());
        bytes.extend_from_slice(&self.ns.to_le_bytes());
        bytes
    }
}

impl TryFrom<&[u8; 48]> for Header {

    type Error = RatchetError;

    /// Converts a vector into a [`Header`].
    ///
    /// # Returns
    ///
    /// * [`Header`] - The decoded [`Header`].
    ///
    /// # Errors
    ///
    /// * [`RatchetError::InvalidHeaderLength`] - Returned if `value` does not match the expected length of [`Header`] ([`Header::LENGTH`]).
    fn try_from(value: &[u8; 48]) -> Result<Self, Self::Error> {
        if value.len() != Self::LENGTH {
            return Err(RatchetError::InvalidHeaderLength(value.len()))
        }
        let dhs = PublicKey::from(array_ref!(value, 0, CURVE25519_PUBLIC_LENGTH));
        let pn = u64::from_le_bytes(
            *array_ref!(
                value,
                CURVE25519_PUBLIC_LENGTH,
                size_of::<u64>()
            )
        );
        let ns = u64::from_le_bytes(
            *array_ref!(
                value,
                CURVE25519_PUBLIC_LENGTH + size_of::<u64>(),
                size_of::<u64>()
            )
        );
        Ok(Self { dhs, pn, ns })
    }
}

/// A [`Ratchet`] represents the Double Ratchet state used for secure message encryption and decryption.
#[derive(Clone)]
pub struct Ratchet {
    /// The local Diffie-Hellman key pair used for sending messages.
    /// For more information, see [`RatchetKeyPair`].
    dh_sending: RatchetKeyPair,

    /// The most recently received public key from the remote party.
    /// For more information, see [`PublicKey`].
    dh_receiving: Option<PublicKey>,

    /// The current root key shared between both parties.
    /// For more information, see [`SharedSecret`].
    root_key: SharedSecret,

    /// The current chain key used for deriving message keys in the sending direction.
    /// For more information, see [`SharedSecret`].
    sending_chain_key: Option<SharedSecret>,

    /// The current chain key used for deriving message keys in the receiving direction.
    /// For more information, see [`SharedSecret`].
    receiving_chain_key: Option<SharedSecret>,

    /// The number of messages sent in the current sending chain.
    n_messages_sent: u64,

    /// The number of messages received in the current receiving chain.
    n_messages_received: u64,

    /// The number of messages sent in the previous sending chain.
    pn: u64,

    /// A map of skipped message keys indexed by (sender public key, message number).
    /// For more information, see [`PublicKey`] and [`SharedSecret`].
    mk_skipped: HashMap<(PublicKey, u64), SharedSecret>,
}


impl Ratchet {

    /// Initializes the ratchet state for Alice (the initiator).
    ///
    /// # Arguments
    ///
    /// * `shared_secret` – The pre-shared secret derived during X3DH or initial key exchange.
    /// * `bob_pk` – Bob's initial public key.
    ///
    /// # Returns
    ///
    /// * [`Ratchet`] - A [`Ratchet`] instance with sending and receiving chain keys set.
    pub fn init_alice(shared_secret: SharedSecret, bob_pk: PublicKey) -> Self {
        // TODO: make sure that also bob start the conversation
        let dh_sending = RatchetKeyPair::new();
        let dh = dh_sending.diffie_hellman(&bob_pk);
        let dh_receiving = Some(bob_pk);
        let (root_key, sending_chain_key) = hkdf_rk(shared_secret.clone(), dh).unwrap();
        let (receiving_chain_key, _) = hkdf_ck(shared_secret).unwrap();

        let n_messages_sent: u64 = 0;
        let n_messages_received: u64 = 0;
        let pn: u64 = 0;
        let mk_skipped = HashMap::new();
        Self {
            dh_sending,
            dh_receiving,
            root_key,
            sending_chain_key: Some(sending_chain_key),
            receiving_chain_key: Some(receiving_chain_key),
            n_messages_sent,
            n_messages_received,
            pn,
            mk_skipped
        }
    }

    /// Initializes the ratchet state for Bob (the receiver).
    ///
    /// # Arguments
    ///
    /// * `shared_secret` – The pre-shared secret derived during X3DH or initial key exchange.
    /// * `dk_sending` – Bob's initial Diffie-Hellman key pair.
    ///
    /// # Returns
    ///
    /// * [`Ratchet`] - A [`Ratchet`] instance with a sending chain key but without a receiving key yet.
    pub fn init_bob(shared_secret: SharedSecret, dk_sending: RatchetKeyPair) -> Self {
        let dh_sending = dk_sending;
        let dh_receiving = None;
        let root_key = shared_secret.clone();
        let (sending_chain_key, _) = hkdf_ck(shared_secret).unwrap();
        let receiving_chain_key = None;
        let n_messages_sent: u64 = 0;
        let n_messages_received: u64 = 0;
        let pn: u64 = 0;
        let mk_skipped = HashMap::new();

        Self {
            dh_sending,
            dh_receiving,
            root_key,
            sending_chain_key: Some(sending_chain_key),
            receiving_chain_key,
            n_messages_sent,
            n_messages_received,
            pn,
            mk_skipped
        }
    }

    /// Encrypts a message using the current sending chain state.
    ///
    /// # Arguments
    ///
    /// * `plaintext` – The message to encrypt.
    /// * `aad` – Associated data to authenticate (but not encrypt).
    ///
    /// # Returns
    ///
    /// * `String` - A base64-encoded ciphertext string.
    /// 
    /// # Errors
    /// 
    /// * [`X3DHError::AesGcmInvalidLength`] - Returned if AES-GCM decryption fails due to an unexpected ciphertext length.
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<String, RatchetError> {
        let (ck, mk) = hkdf_ck(self.sending_chain_key.clone().unwrap())?;
        self.sending_chain_key = Some(ck);
        let h = Header::new(self.dh_sending.public_key.clone(), self.pn, self.n_messages_sent);
        self.n_messages_sent += 1;
        let mk = EncryptionKey::from(mk);
        // Generate a new aad prepending the header to the original aad
        let mut new_aad = vec![];
        new_aad.extend_from_slice(&h.to_bytes());
        new_aad.extend_from_slice(&aad);
        Ok(mk.encrypt(plaintext, &new_aad)?)
    }

    /// Decrypts a received message, performing ratchet step if necessary.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` – The base64-encoded encrypted message.
    ///
    /// # Returns
    ///
    /// * `Vec<u8>` - The decrypted plaintext message.
    /// 
    /// # Errors
    /// 
    /// * [`RatchetError::ConversionError`] - Returned if Base64 decoding of the ciphertext or conversion to `AssociatedData` fails.
    /// * [`RatchetError::InvalidHeaderLength`] - Returned if `value` does not match the expected length of [`Header`] ([`Header::LENGTH`]).
    /// * [`X3DHError::AesGcmInvalidLength`] - Returned if AES-GCM decryption fails due to an unexpected ciphertext length.
    /// * [`RatchetError::MaxSkipsExceeded`] - Returned if the number of skipped messages exceeds the allowed maximum when attempting to handle out-of-order messages or advance the ratchet state.
    pub fn decrypt(&mut self, ciphertext: String) -> Result<Vec<u8>, RatchetError> {
        let ciphertext = general_purpose::STANDARD.decode(ciphertext).map_err(|_| {
            ConversionError
        })?;
        let nonce = *array_ref!(&ciphertext, 0, AES256_NONCE_LENGTH);
        let header = Header::try_from(array_ref!(&ciphertext, AES256_NONCE_LENGTH, Header::LENGTH))?;
        let aad = AssociatedData::try_from(array_ref!(
            &ciphertext,
            AES256_NONCE_LENGTH + Header::LENGTH,
            AssociatedData::SIZE
        )).map_err(|_| ConversionError)?;

        let ciphertext = &ciphertext[AES256_NONCE_LENGTH + Header::LENGTH + AssociatedData::SIZE..];
        let plaintext = self.try_skipped_message_keys(header.clone(), ciphertext, aad.clone(), &nonce)?;
        if plaintext.is_some() {
            return Ok(plaintext.unwrap());
        }
        if self.sending_chain_key.is_none() || Some(header.dhs.clone()) != self.dh_receiving.clone() {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(header.clone())?;
        }
        self.skip_message_keys(header.ns)?;
        let (ckr, mk) = hkdf_ck(self.receiving_chain_key.clone().unwrap())?;
        self.receiving_chain_key = Some(ckr);
        let mk = DecryptionKey::from(mk);
        self.n_messages_received += 1;
        let mut new_aad = vec![];
        new_aad.extend_from_slice(&header.to_bytes());
        new_aad.extend_from_slice(&aad.clone().to_bytes());
        Ok(mk.decrypt(ciphertext, &nonce, &new_aad)?)

    }

    /// Attempts to decrypt the message using any skipped keys.
    /// This function checks whether a message key corresponding to the given header
    /// and message number has been stored in the `mk_skipped` map. If found, it uses
    /// that key to decrypt the message. This allows the receiver to handle out-of-order
    /// messages or skipped messages without losing forward secrecy. 
    /// 
    /// # Arguments
    ///
    /// * `header` - The message header containing the sender's public key and message number.
    /// * `ciphertext` - The encrypted message payload (excluding nonce, header, and AAD).
    /// * `aad` - The associated data used to authenticate the message.
    /// * `nonce` - The nonce used during encryption.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(plaintext))` - If a matching skipped message key was found and decryption succeeded.
    /// * `Ok(None)` - If no matching skipped message key was found.
    /// 
    /// # Errors
    /// 
    /// * [`X3DHError::AesGcmInvalidLength`] - Returned if AES-GCM decryption fails due to an unexpected ciphertext length. 
    fn try_skipped_message_keys(
        &mut self,
        header: Header,
        ciphertext: &[u8],
        aad: AssociatedData,
        nonce: &[u8; AES256_NONCE_LENGTH]
    ) -> Result<Option<Vec<u8>>, RatchetError> {
        if self.mk_skipped.contains_key(&(header.dhs.clone(), header.ns)) {
            let mk = self.mk_skipped.get(&(header.dhs.clone(), header.ns)).unwrap();
            let mk = DecryptionKey::from(mk.clone());
            self.mk_skipped.remove(&(header.dhs.clone(), header.ns));
            let mut tmp = vec![];
            tmp.extend_from_slice(&header.to_bytes());
            tmp.extend_from_slice(&aad.to_bytes());
            Ok(Some(mk.decrypt(ciphertext, nonce, &tmp)?))
        } else {
            Ok(None)
        }
    }

    /// Skips message keys up to a given message number and stores them.
    ///
    /// # Arguments
    ///
    /// * `until` – The message number to skip up to (exclusive).
    fn skip_message_keys(&mut self, until: u64) -> Result<(), RatchetError> {
        if self.n_messages_received + MAX_SKIPS < until {
            return Err(RatchetError::MaxSkipsExceeded);
        } else if self.receiving_chain_key.is_some() {
            while self.n_messages_received < until {
                let (ck, mk) = hkdf_ck(self.receiving_chain_key.clone().unwrap())?;
                self.receiving_chain_key = Some(ck);
                let mk = SharedSecret::from(mk);
                self.mk_skipped.insert(
                    (self.dh_receiving.clone().unwrap(), self.n_messages_sent),
                    mk,
                );

                self.n_messages_sent += 1;
            }
        }
        Ok(())
    }

    /// Performs a DH ratchet step: updates keys and state for a new incoming public key.
    ///
    /// # Arguments
    ///
    /// * `header` – The header containing the new public key.
    fn dh_ratchet(&mut self, header: Header) -> Result<(), RatchetError> {
        self.pn = self.n_messages_sent;
        self.n_messages_sent = 0;
        self.n_messages_received = 0;
        self.dh_receiving = Some(header.dhs);
        let (rk, ckr) = hkdf_rk(
            self.root_key.clone(),
            self.dh_sending.diffie_hellman(&self.dh_receiving.clone().unwrap())
        )?;

        self.root_key = rk;
        self.receiving_chain_key = Some(ckr);
        self.dh_sending = RatchetKeyPair::new();
        let (rk, cks) = hkdf_rk(
            self.root_key.clone(),
            self.dh_sending.diffie_hellman(&self.dh_receiving.clone().unwrap())
        )?;
        self.root_key = rk;
        self.sending_chain_key = Some(cks);
        Ok(())
    }
}

/// Derives a new root key and chain key from the current root key and a Diffie-Hellman shared secret.
/// This function implements the `HKDF(rk, dh)` step from the Double Ratchet algorithm, using the current
/// root key `rk` and a new shared secret `dh` as inputs. It applies HKDF with SHA-256 to produce two
/// new secrets: a derived root key and a new receiving chain key.
///
/// # Arguments
///
/// * `rk` - The current root key (a shared secret).
/// * `dh` - The Diffie-Hellman shared secret between the new and previous public keys.
///
/// # Returns
///
/// * ([`SharedSecret`], [`SharedSecret`]) - A tuple `(new_root_key, receiving_chain_key)` derived from HKDF.
///
/// # Errors
///
/// * [`RatchetError::KeyDerivationError`] - If the HKDF expand step fails.
fn hkdf_rk(
    rk: SharedSecret,
    dh: SharedSecret,
) -> Result<(SharedSecret, SharedSecret), RatchetError> {
    let info = b"RatchtetInfo";
    // HKDF input key material = F || KM, where KM is an input byte sequence containing secret key material, and F is a byte sequence containing 32 0xFF bytes if curve is X25519, and 57 0xFF bytes if curve is X448. F is used for cryptographic domain separation with XEdDSA [2].
    let mut dhs = vec![0xFFu8; 32];
    dhs.extend_from_slice(rk.as_ref());
    dhs.extend_from_slice(dh.as_ref());

    // Use the shared secret as the salt as per the X3DH spec.
    let hk = Hkdf::<Sha256>::new(Some(rk.as_ref()), dhs.as_ref());
    let mut okm = [0u8; 2 * AES256_SECRET_LENGTH];
    // HKDF info = The info parameter from Section 2.1.
    hk.expand(info, &mut okm)?;

    let shared_key1 = SharedSecret::from(*array_ref!(okm, 0, AES256_SECRET_LENGTH));
    let shared_key2 =
        SharedSecret::from(*array_ref!(okm, AES256_SECRET_LENGTH, AES256_SECRET_LENGTH));
    Ok((shared_key1, shared_key2))
}

/// Derives a new chain key and message key from the current chain key using HKDF.
/// This function applies HKDF with SHA-256 to derive two secrets from a single chain key:
/// the next chain key and a message encryption key. This step is used for each message sent or received
/// in the Double Ratchet protocol to ensure forward secrecy.
///
/// # Arguments
///
/// * `ck` - The current chain key, a [`SharedSecret`] used as input key material for HKDF.
///
/// # Returns
///
/// * ([`SharedSecret`], [`SharedSecret`]) - A tuple `(next_chain_key, message_key)` used to continue the ratchet chain and encrypt/decrypt a message.
///
/// # Errors
///
/// * [`RatchetError::KeyDerivationError`] - if HKDF expansion fails.
fn hkdf_ck(
    ck: SharedSecret,
) -> Result<(SharedSecret, SharedSecret), RatchetError> {
    // HKDF salt = A zero-filled byte sequence with length equal to the hash output length.
    let hk = Hkdf::<Sha256>::new(None, ck.as_ref());
    let mut chain_key = [0u8; AES256_SECRET_LENGTH];
    let mut message_key = [0u8; AES256_SECRET_LENGTH];
    // HKDF info = The info parameter from Section 2.1.
    hk.expand(b"ChainKey", &mut chain_key)?;
    hk.expand(b"MessageKey", &mut message_key)?;

    let chain_key = SharedSecret::from(*array_ref!(chain_key, 0, AES256_SECRET_LENGTH));
    let message_key =
        SharedSecret::from(*array_ref!(message_key, 0, AES256_SECRET_LENGTH));
    Ok((chain_key, message_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::SharedSecret;
    use aes_gcm::{KeyInit};

    #[test]
    fn test_ratchet() {

        // test 1: simple ratchet exchange
        let bob_ratchet = RatchetKeyPair::new();
        let sh = SharedSecret::from([0u8; 32]);
        let mut alice = Ratchet::init_alice(sh.clone(), bob_ratchet.public_key.clone());
        let mut bob = Ratchet::init_bob(sh, bob_ratchet.clone());
        let plaintext = b"Hello, Bob!";
        let aad = AssociatedData{
            initiator_identity_key: bob_ratchet.public_key.clone(),
            responder_identity_key: alice.dh_sending.public_key.clone(),
        };
        let ciphertext = alice.encrypt(plaintext, &aad.to_bytes()).unwrap();
        let decrypted = match bob.decrypt(ciphertext) {
            Ok(dec) => dec,
            Err(e) => {
                panic!("Decryption failed: {:?}", e);
            }
        };
        assert_eq!(decrypted, plaintext);
        let plaintext = b"Hello, Alice!";
        let aad = AssociatedData{
            initiator_identity_key: bob_ratchet.public_key.clone(),
            responder_identity_key: alice.dh_sending.public_key.clone(),
        };
        let ciphertext = bob.encrypt(plaintext, &aad.to_bytes()).unwrap();
        let decrypted = match alice.decrypt(ciphertext) {
            Ok(dec) => dec,
            Err(e) => {
                panic!("Decryption failed: {:?}", e);
            }
        };
        assert_eq!(decrypted, plaintext);

        // test 2: ratchet exchange with skipped message keys
        let plaintext = b"How are you, Alice?";
        let aad = AssociatedData{
            initiator_identity_key: bob_ratchet.public_key.clone(),
            responder_identity_key: alice.dh_sending.public_key.clone(),
        };
        let ciphertext = bob.encrypt(plaintext, &aad.to_bytes()).unwrap();
        let decrypted = match alice.decrypt(ciphertext) {
            Ok(dec) => dec,
            Err(e) => {
                panic!("Decryption failed: {:?}", e);
            }
        };
        assert_eq!(decrypted, plaintext);

        let plaintext = b"All good, Bob!";
        let aad = AssociatedData{
            initiator_identity_key: bob_ratchet.public_key.clone(),
            responder_identity_key: alice.dh_sending.public_key.clone(),
        };
        let ciphertext = alice.encrypt(plaintext, &aad.to_bytes()).unwrap();
        let decrypted = match bob.decrypt(ciphertext) {
            Ok(dec) => dec,
            Err(e) => {
                panic!("Decryption failed: {:?}", e);
            }
        };
    }
}