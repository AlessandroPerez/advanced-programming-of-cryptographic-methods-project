use serde::{Deserialize, Serialize};
use std::fs;
use protocol::utils::{PrivateKey, PublicKey};


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
    let file_path = "./config/config.toml";

    // Step 1: Read the content of the file
    let config_content = fs::read_to_string(file_path)?;

    let new_private_key = PrivateKey::new();
    let new_public_key = PublicKey::from(&new_private_key);

    // Step 2: Deserialize the content into a Config struct
    let mut config: Config = toml::from_str(&config_content)?;

    // Step 3: Modify the keys
    config.private_key_server = new_private_key.to_base64();
    config.public_key_server = new_public_key.to_base64();


    // Step 4: Serialize the updated struct back to TOML
    let updated_content = toml::to_string(&config)?;

    // Step 5: Write the updated content back to the file
    fs::write(file_path, updated_content)?;

    println!("Config updated successfully!");

    Ok(())
}

