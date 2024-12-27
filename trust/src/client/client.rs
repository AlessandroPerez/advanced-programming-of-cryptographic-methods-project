use std::error::Error;
use ed25519_dalek::VerifyingKey;
use reqwest;
use crate::protocol::x3dh::{generate_identity_keypair, generate_signed_prekey, generate_one_time_prekey, generate_prekey_bundle, deserialize_signed_prekey, derive_shared_secret};
use serde_json;
use x25519_dalek::PublicKey;


pub async fn register_user(username: &str, server_url: &str) -> Result<(), Box<dyn Error>> {
    let (identity_key, identity_verifying_key) = generate_identity_keypair();
    let (_, signed_prekey) = generate_signed_prekey(&identity_key);
    let (_, one_time_public) = generate_one_time_prekey();

    let (verify_key, _) = deserialize_signed_prekey(&signed_prekey).unwrap();

    let registration_data = serde_json::json!({
        "username": username,
        "identity_key": identity_verifying_key.to_bytes(),
        "signed_prekey": verify_key.to_bytes(),
        "signature": signed_prekey.signature,
        "one_time_prekey": one_time_public.to_bytes(),
    });

    let client = reqwest::Client::new();
    let response = client.post(server_url)
        .json(&registration_data)
        .send()
        .await?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err("Failed to register user".into())
    }

    // todo!("Implement TLS connection with self-signed certificate");
}
