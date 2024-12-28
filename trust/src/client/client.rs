use std::error::Error;
use reqwest;
use serde_json;
use reqwest::Client;
use crate::protocol::x3dh::{
    generate_identity_keypair,
    generate_signed_prekey,
    deserialize_signed_prekey,
    generate_one_time_prekey
};


/// Create a `reqwest` client configured to accept invalid certificates.
/// This is useful for development with self-signed certificates.
pub fn create_client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true) // Accept self-signed certificates
        .build()
        .expect("Failed to build HTTP client")
}

/// Example function to send a GET request to the server.
pub async fn send_get_request() -> Result<String, reqwest::Error> {
    let client = create_client();
    let response = client
        .get("https://127.0.0.1:3030/hello")
        .send()
        .await?;

    response.text().await
}

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

    let client = create_client();
    let response = client.post(server_url)
        .json(&registration_data)
        .send()
        .await?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err("Failed to register user".into())
    }
}
