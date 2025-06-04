use serde::{Deserialize, Serialize};
use std::fs;
use protocol::utils::{PrivateKey, PublicKey};
use std::path::Path;

fn is_running_in_docker() -> bool {
    Path::new("/.dockerenv").exists()
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    server_ip: String,
    server_port: String,
    private_key_server: String,
    public_key_server: String,
    log_level: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Path to the config.toml file
    let file_path = if is_running_in_docker() {
        "/app/config/config.toml"
    } else {
        "config/config.toml"
    };

    let config_content = fs::read_to_string(file_path)?;

    let new_private_key = PrivateKey::new();
    let new_public_key = PublicKey::from(&new_private_key);

    let mut config: Config = toml::from_str(&config_content)?;

    config.private_key_server = new_private_key.to_base64();
    config.public_key_server = new_public_key.to_base64();


    let updated_content = toml::to_string(&config)?;

    fs::write(file_path, updated_content)?;

    println!("Config updated successfully!");

    Ok(())
}

