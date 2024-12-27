use x25519_dalek::{EphemeralSecret, PublicKey};
use ed25519_dalek::{SigningKey, Signature, VerifyingKey, Signer, Verifier};
use rand::rngs::OsRng;
use sha2::{Sha512, Digest, Sha256};
use serde::{Serialize, Deserialize};
use serde_bytes;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
pub struct FixedArray64(#[serde(with = "serde_bytes")] pub [u8; 64]);

#[derive(Serialize, Deserialize)]
pub struct FixedArray32(#[serde(with = "serde_bytes")] pub [u8; 32]);

#[derive(Serialize, Deserialize)]
pub struct PrekeyBundle {
    pub identity_key: FixedArray32,
    pub signed_prekey: FixedArray32,
    pub signed_prekey_signature: FixedArray64,
    pub one_time_prekey: Option<FixedArray32>,
}

#[derive(Serialize, Deserialize)]
pub struct SessionInitMessage {
    pub sender_identity_key: FixedArray32,
    pub sender_ephemeral_key: FixedArray32,
    pub receiver_prekey_bundle: PrekeyBundle,
    pub timestamp: u64,
}

// Generate identity keypair
pub fn generate_identity_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    (signing_key, verifying_key)
}

// Generate signed prekey pair
pub fn generate_signed_prekey(identity_key: &SigningKey) -> (SigningKey, VerifyingKey, Signature) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let signature = identity_key.sign(&verifying_key.to_bytes());
    (signing_key, verifying_key, signature)
}

// Generate one-time prekey
pub fn generate_one_time_prekey() -> (EphemeralSecret, PublicKey) {
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut OsRng);
    let public_key = PublicKey::from(&ephemeral_secret);
    (ephemeral_secret, public_key)
}

pub fn generate_prekey_bundle(
    identity_key: &SigningKey,
    signed_prekey: (SigningKey, VerifyingKey, Signature),
    one_time_prekey: Option<(EphemeralSecret, PublicKey)>,
) -> PrekeyBundle {
    PrekeyBundle {
        identity_key: FixedArray32(identity_key.verifying_key().to_bytes()),
        signed_prekey: FixedArray32(signed_prekey.1.to_bytes()),
        signed_prekey_signature: FixedArray64(signed_prekey.2.to_bytes()),
        one_time_prekey: one_time_prekey.map(|(_, pk)| FixedArray32(*pk.as_bytes())),
    }
}

pub fn create_session_init_message(
    sender_identity_key: &SigningKey,
    receiver_prekey_bundle: PrekeyBundle,
) -> SessionInitMessage {
    let (_ephemeral_secret, ephemeral_public) = generate_one_time_prekey();

    SessionInitMessage {
        sender_identity_key: FixedArray32(sender_identity_key.verifying_key().to_bytes()),
        sender_ephemeral_key:FixedArray32(*ephemeral_public.as_bytes()),
        receiver_prekey_bundle,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs(),
    }
}

/// Derive a shared secret using Diffie-Hellman key exchange.
pub fn derive_shared_secret(private_key: EphemeralSecret, public_key: &PublicKey) -> [u8; 32] {
    private_key.diffie_hellman(public_key).to_bytes()
}

/// Calculate the final shared secret by hashing multiple DH results.
pub fn kdf(
    dh1: [u8; 32],
    dh2: [u8; 32],
    dh3: [u8; 32],
    dh4: Option<[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(dh1);
    hasher.update(dh2);
    hasher.update(dh3);
    if let Some(dh4) = dh4 {
        hasher.update(dh4);
    }
    let hash = hasher.finalize();
    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&hash[..32]);
    shared_secret
}

pub fn validate_signed_prekey(
    identity_verifying_key: &VerifyingKey,
    signed_prekey: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    let verifying_key = VerifyingKey::from_bytes(identity_verifying_key.as_bytes()).unwrap();
    verifying_key.verify(signed_prekey, &Signature::from(signature)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier; // For verifying signatures

    #[test]
    fn test_generate_identity_keypair() {
        let (signing_key, verifying_key) = generate_identity_keypair();
        assert_eq!(signing_key.to_bytes().len(), 32, "SigningKey should be 32 bytes");
        assert_eq!(verifying_key.to_bytes().len(), 32, "VerifyingKey should be 32 bytes");
    }

    #[test]
    fn test_generate_signed_prekey() {
        let (identity_key, _) = generate_identity_keypair();
        let (signing_key, verifying_key, signature) = generate_signed_prekey(&identity_key);

        // Verify the signed prekey's signature
        assert!(identity_key
            .verifying_key()
            .verify(verifying_key.as_bytes(), &signature)
            .is_ok());

        assert_eq!(signing_key.to_bytes().len(), 32, "SigningKey should be 32 bytes");
        assert_eq!(verifying_key.to_bytes().len(), 32, "VerifyingKey should be 32 bytes");
    }

    #[test]
    fn test_generate_one_time_prekey() {
        let (secret, public_key) = generate_one_time_prekey();
        // assert_eq!(secret.as_bytes().len(), 32, "EphemeralSecret should be 32 bytes");
        assert_eq!(public_key.as_bytes().len(), 32, "PublicKey should be 32 bytes");
    }

    #[test]
    fn test_generate_prekey_bundle() {
        let (identity_key, _) = generate_identity_keypair();
        let (signed_prekey_signing, signed_prekey_verifying, signature) =
            generate_signed_prekey(&identity_key);
        let one_time_prekey = Some(generate_one_time_prekey());

        let bundle = generate_prekey_bundle(
            &identity_key,
            (signed_prekey_signing, signed_prekey_verifying, signature),
            one_time_prekey,
        );

        assert_eq!(bundle.identity_key.0.len(), 32);
        assert_eq!(bundle.signed_prekey.0.len(), 32);
        assert_eq!(bundle.signed_prekey_signature.0.len(), 64);

        if let Some(otp) = bundle.one_time_prekey {
            assert_eq!(otp.0.len(), 32);
        }
    }

    #[test]
    fn test_prekey_bundle_serialization() {
        let (identity_key, _) = generate_identity_keypair();
        let (signed_prekey_signing, signed_prekey_verifying, signature) =
            generate_signed_prekey(&identity_key);
        let one_time_prekey = Some(generate_one_time_prekey());

        let bundle = generate_prekey_bundle(
            &identity_key,
            (signed_prekey_signing, signed_prekey_verifying, signature),
            one_time_prekey,
        );

        // Serialize to JSON
        let serialized = serde_json::to_string(&bundle).expect("Failed to serialize bundle");

        // Deserialize back to a PrekeyBundle
        let deserialized: PrekeyBundle =
            serde_json::from_str(&serialized).expect("Failed to deserialize bundle");

        // Verify that deserialization matches the original bundle
        assert_eq!(bundle.identity_key.0, deserialized.identity_key.0);
        assert_eq!(bundle.signed_prekey.0, deserialized.signed_prekey.0);
        assert_eq!(
            bundle.signed_prekey_signature.0,
            deserialized.signed_prekey_signature.0
        );

        if let (Some(otp), Some(des_otp)) = (&bundle.one_time_prekey, &deserialized.one_time_prekey)
        {
            assert_eq!(otp.0, des_otp.0);
        }
    }
}




