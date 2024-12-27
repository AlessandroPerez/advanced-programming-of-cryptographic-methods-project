use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Serialize, Deserialize};
use serde_json;
use aes_gcm::{aead::{Aead, KeyInit, OsRng}, AeadCore, Aes256Gcm, Key, Nonce};

/// Encrypts a message using AES-GCM with the derived shared secret
pub fn encrypt_message(shared_secret: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let key = Key::<Aes256Gcm>::from_slice(shared_secret); // Use the shared secret as the key
    let cipher = Aes256Gcm::new(key);

    // Generate a random nonce (12 bytes for AES-GCM)
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 12-byte nonce

    // Encrypt the plaintext
    cipher
        .encrypt(&nonce, plaintext)
        .map(|ciphertext| (ciphertext, nonce.to_vec()))
        .map_err(|e| format!("Encryption failed: {}", e))
}

/// Decrypts a message using AES-GCM with the derived shared secret
pub fn decrypt_message(shared_secret: &[u8; 32], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let key = Key::<Aes256Gcm>::from_slice(shared_secret);
    let cipher = Aes256Gcm::new(key);

    // Decrypt the ciphertext
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))
}

// HMAC-SHA256
pub fn generate_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("Invalid HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}
pub fn serialize<T: Serialize>(data: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(data)
}

pub fn deserialize<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    /// Generate a random 256-bit key
    pub fn generate_random_key() -> [u8; 32] {
        let mut key = [0u8; 32]; // 256 bits
        OsRng.fill_bytes(&mut key);
        key
    }


    #[test]
    fn test_encrypt_decrypt_message_aes_gcm() {
        let shared_secret = generate_random_key(); // Replace with actual shared secret from X3DH
        let message = b"Hello, encrypted world with AES-GCM!";

        let (ciphertext, nonce) = encrypt_message(&shared_secret, message).expect("Encryption failed");
        let decrypted_message = decrypt_message(&shared_secret, &ciphertext, &nonce).expect("Decryption failed");

        assert_eq!(decrypted_message, message);
    }
}

