mod client;
mod protocol;
mod config;
mod server;

use std::env;
use log::error;
use reqwest::Client;
use tokio::main;
use crate::server::server::start_server;

#[tokio::main]
async fn main() {
    use server;

    let args: Vec<String> = env::args().collect();
    if args.len() > 2 {
        error!("Usage: {} [client | server]", args[0]);
    }

    match args[1].as_str() {
        "client" => {
            let client = Client::builder()
                .danger_accept_invalid_certs(true) // For testing with self-signed certs
                .build()
                .unwrap();

            let payload = serde_json::json!({
                "username": "test_user",
                "password": "test_password",
                "identity_key": vec![0; 32],       // Use `vec![0; 32]` for a 32-byte array
                "signed_prekey": vec![0; 32],
                "signature": vec![0; 64],         // Use `vec![0; 64]` for a 64-byte array
                "one_time_prekey": vec![0; 32]
            });

            let response = client
                .post("https://127.0.0.1:3030/register")
                .json(&payload)
                .send()
                .await;

            match response {
                Ok(res) => {
                    println!("Response: {:?}", res.text().await.unwrap());
                }
                Err(e) => {
                    eprintln!("Error: {:?}", e);
                }
            }
        },
        "server" => start_server().await,
        _ => error!("Invalid option. Use 'client' or 'server'"),
    }
}