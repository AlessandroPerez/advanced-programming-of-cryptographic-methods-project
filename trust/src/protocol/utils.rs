use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Serialize, Deserialize};
use serde_json;

// HMAC-SHA256
pub fn generate_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}
pub fn serialize<T: Serialize>(data: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(data)
}

pub fn deserialize<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice(bytes)
}
