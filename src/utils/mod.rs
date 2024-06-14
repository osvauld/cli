use base64::{decode, encode};
use dirs::home_dir;
use serde::Deserialize;
use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

#[derive(Deserialize)]
pub struct Config {
    pub enc_public_key: String,
    pub enc_private_key: String,
    pub sign_public_key: String,
    pub sign_private_key: String,
    pub base_url: String,
}

pub fn save_to_file(dir: &PathBuf, filename: &str, content: &[u8]) -> Result<(), Box<dyn Error>> {
    let file_path = dir.join(filename);
    let mut file = File::create(file_path)?;
    file.write_all(content)?;
    Ok(())
}

pub fn load_config_files() -> Result<Config, Box<dyn Error>> {
    let home_dir = home_dir().ok_or("Could not find home directory")?;
    let osvauld_dir = home_dir.join(".osvauld");

    let base_url = fs::read_to_string(osvauld_dir.join("baseUrl.txt"))?;
    let sign_public_key = fs::read(osvauld_dir.join("sign_public_key.asc"))?;
    let sign_private_key = fs::read(osvauld_dir.join("sign_private_key.asc"))?;
    let enc_public_key = fs::read(osvauld_dir.join("enc_public_key.asc"))?;
    let enc_private_key = fs::read(osvauld_dir.join("enc_private_key.asc"))?;

    let config = Config {
        enc_public_key: encode(enc_public_key),
        enc_private_key: encode(enc_private_key),
        sign_public_key: encode(sign_public_key),
        sign_private_key: encode(sign_private_key),
        base_url: base_url,
    };

    Ok(config)
}

pub fn init_command(config: &str) -> Result<(), Box<dyn Error>> {
    // Decode the base64 encoded config string
    let decoded = decode(config)?;
    let config_str = String::from_utf8(decoded)?;

    // Deserialize the config string to the Config struct
    let config: Config = serde_json::from_str(&config_str)?;

    // Decode the base64 encoded values
    let enc_public_key = decode(&config.enc_public_key)?;
    let enc_private_key = decode(&config.enc_private_key)?;
    let sign_public_key = decode(&config.sign_public_key)?;
    let sign_private_key = decode(&config.sign_private_key)?;

    // Get the .osvauld directory in the home directory
    let home_dir = home_dir().ok_or("Could not find home directory")?;
    let osvauld_dir = home_dir.join(".osvauld");
    fs::create_dir_all(&osvauld_dir)?;

    // Save the keys and baseUrl to files
    save_to_file(&osvauld_dir, "enc_public_key.asc", &enc_public_key)?;
    save_to_file(&osvauld_dir, "enc_private_key.asc", &enc_private_key)?;
    save_to_file(&osvauld_dir, "sign_public_key.asc", &sign_public_key)?;
    save_to_file(&osvauld_dir, "sign_private_key.asc", &sign_private_key)?;
    save_to_file(&osvauld_dir, "baseUrl.txt", config.base_url.as_bytes())?;

    println!("Configuration saved to ~/.osvauld");

    Ok(())
}
