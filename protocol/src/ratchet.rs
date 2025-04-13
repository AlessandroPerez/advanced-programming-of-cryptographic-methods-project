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
use crate::errors::DRError;
use crate::errors::DRError::ConversionError;

#[derive(Clone)]
struct RatchetKeyPair {
    public_key: PublicKey,
    private_key: PrivateKey,
}

impl RatchetKeyPair {
    pub fn new() -> Self {
        let private_key = PrivateKey::new();
        let public_key = PublicKey::from(&private_key);
        Self {
            public_key,
            private_key,
        }
    }

    fn diffie_hellman(
        &self,
        other_public_key: &PublicKey,
    ) -> SharedSecret {
        self.private_key.diffie_hellman(other_public_key)
    }
}

#[derive(Clone)]
struct Header {
    dhs : PublicKey,
    pn: u64,
    ns: u64,
}

impl Header {
    const LENGTH: usize = AES256_SECRET_LENGTH + 8 + 8;
    pub fn new(dhs: PublicKey, pn: u64, ns: u64) -> Self {
        Self { dhs, pn, ns }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.dhs.as_ref());
        bytes.extend_from_slice(&self.pn.to_le_bytes());
        bytes.extend_from_slice(&self.ns.to_le_bytes());
        bytes
    }
}

impl TryFrom<&[u8; 48]> for Header {

    type Error = DRError;

    fn try_from(value: &[u8; 48]) -> Result<Self, Self::Error> {
        if value.len() != Self::LENGTH {
            return Err(DRError::InvalidHeaderLength(value.len()))
        }
        let dhs = PublicKey::from(array_ref!(value, 0, CURVE25519_PUBLIC_LENGTH));
        let pn = u64::from_le_bytes(*array_ref!(value, CURVE25519_PUBLIC_LENGTH, 8));
        let ns = u64::from_le_bytes(*array_ref!(value, CURVE25519_PUBLIC_LENGTH + 8, 8));
        Ok(Self { dhs, pn, ns })
    }
}

struct Ratchet {
    dh_sending: RatchetKeyPair,
    dh_receiving: Option<PublicKey>,
    root_key: SharedSecret,
    sending_chain_key: Option<SharedSecret>,
    receiving_chain_key: Option<SharedSecret>,
    n_messages_sent: u64,
    n_messages_received: u64,
    pn: u64,
    mk_skipped: HashMap<(PublicKey, u64), SharedSecret>
}


impl Ratchet {
    pub fn init_alice(shared_secret: SharedSecret, bob_pk: PublicKey) -> Self {
        let dh_sending = RatchetKeyPair::new();
        let dh = dh_sending.diffie_hellman(&bob_pk);
        let dh_receiving = Some(bob_pk);
        let (root_key, sending_chain_key) = hkdf_rk(shared_secret, dh).unwrap();
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
    pub fn init_bob(shared_secret: SharedSecret, dk_sending: RatchetKeyPair) -> Self {
        let dh_sending = dk_sending;
        let dh_receiving = None;
        let root_key = shared_secret;
        let sending_chain_key = None;
        let receiving_chain_key = None;
        let n_messages_sent: u64 = 0;
        let n_messages_received: u64 = 0;
        let pn: u64 = 0;
        let mk_skipped = HashMap::new();

        Self {
            dh_sending,
            dh_receiving,
            root_key,
            sending_chain_key,
            receiving_chain_key,
            n_messages_sent,
            n_messages_received,
            pn,
            mk_skipped
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<String, DRError> {
        let (ck, mk) = hkdf_ck(self.sending_chain_key.clone().unwrap())?;
        self.sending_chain_key = Some(ck);
        let h = Header::new(self.dh_sending.public_key.clone(), self.pn, self.n_messages_sent);
        self.n_messages_sent += 1;
        let mk = EncryptionKey::from(mk);
        let mut tmp = vec![];
        tmp.extend_from_slice(&h.to_bytes());
        tmp.extend_from_slice(&aad);
        Ok(mk.encrypt(plaintext, &tmp)?)
    }

    pub fn decrypt(&mut self, ciphertext: String) -> Result<Vec<u8>, DRError> {
        let ciphertext = general_purpose::STANDARD.decode(ciphertext).map_err(|_| {
            DRError::ConversionError
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
        if self.sending_chain_key.is_none() || header.dhs != self.dh_receiving.clone().unwrap() {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(header.clone())?;
        }
        self.skip_message_keys(header.ns)?;
        let (ckr, mk) = hkdf_ck(self.receiving_chain_key.clone().unwrap())?;
        self.receiving_chain_key = Some(ckr);
        let mk = DecryptionKey::from(mk);
        self.n_messages_received += 1;
        let mut tmp = vec![];
        tmp.extend_from_slice(&header.to_bytes());
        tmp.extend_from_slice(&aad.clone().to_bytes());
        Ok(mk.decrypt(ciphertext, &nonce, &tmp)?)

    }

    fn try_skipped_message_keys(
        &mut self,
        header: Header,
        ciphertext: &[u8],
        aad: AssociatedData,
        nonce: &[u8; AES256_NONCE_LENGTH]
    ) -> Result<Option<Vec<u8>>, DRError> {
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

    fn skip_message_keys(&mut self, until: u64) -> Result<(), DRError> {
        if self.n_messages_received + MAX_SKIPS < until {
            return Err(DRError::MaxSkipsExceeded);
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

    fn dh_ratchet(&mut self, header: Header) -> Result<(), DRError> {
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


fn hkdf_rk(
    rk: SharedSecret,
    dh: SharedSecret,
) -> Result<(SharedSecret, SharedSecret), DRError> {
    let info = b"";
    // HKDF input key material = F || KM, where KM is an input byte sequence containing secret key material, and F is a byte sequence containing 32 0xFF bytes if curve is X25519, and 57 0xFF bytes if curve is X448. F is used for cryptographic domain separation with XEdDSA [2].
    let mut dhs = vec![0xFFu8; 32];
    dhs.extend_from_slice(rk.as_ref());
    dhs.extend_from_slice(dh.as_ref());
    // HKDF salt = A zero-filled byte sequence with length equal to the hash output length.
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), dhs.as_ref());
    let mut okm = [0u8; 2 * AES256_SECRET_LENGTH];
    // HKDF info = The info parameter from Section 2.1.
    hk.expand(info, &mut okm)?;

    let shared_key1 = SharedSecret::from(*array_ref!(okm, 0, AES256_SECRET_LENGTH));
    let shared_key2 =
        SharedSecret::from(*array_ref!(okm, AES256_SECRET_LENGTH, AES256_SECRET_LENGTH));
    Ok((shared_key1, shared_key2))
}

fn hkdf_ck(
    ck: SharedSecret,
) -> Result<(SharedSecret, SharedSecret), DRError> {
    let info = b"";
    // HKDF input key material = F || KM, where KM is an input byte sequence containing secret key material, and F is a byte sequence containing 32 0xFF bytes if curve is X25519, and 57 0xFF bytes if curve is X448. F is used for cryptographic domain separation with XEdDSA [2].
    let mut dhs = vec![0xFFu8; 32];
    dhs.extend_from_slice(ck.as_ref());
    // HKDF salt = A zero-filled byte sequence with length equal to the hash output length.
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), dhs.as_ref());
    let mut okm = [0u8; 2 * AES256_SECRET_LENGTH];
    // HKDF info = The info parameter from Section 2.1.
    hk.expand(info, &mut okm)?;

    let shared_key1 = SharedSecret::from(*array_ref!(okm, 0, AES256_SECRET_LENGTH));
    let shared_key2 =
        SharedSecret::from(*array_ref!(okm, AES256_SECRET_LENGTH, AES256_SECRET_LENGTH));
    Ok((shared_key1, shared_key2))
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