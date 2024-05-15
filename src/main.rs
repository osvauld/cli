use base64::encode;
use clap::{Parser, Subcommand};
use dirs::home_dir;
use openpgp::cert::prelude::*;
use openpgp::crypto::KeyPair;
use openpgp::parse::Parse;
use openpgp::serialize::stream::*;
use reqwest::blocking::Client;
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "My CLI Tool")]
#[command(version = "1.0")]
#[command(about = "A CLI tool for managing configurations and authentication", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the configuration by decoding a base64 string
    Init {
        /// Base64 encoded configuration string
        #[arg(short, long)]
        config: String,
    },
    /// Authenticate using the environment name
    Auth {
        /// Environment name
        #[arg(short, long)]
        envname: String,
    },
}

#[derive(Deserialize)]
struct Config {
    enc_public_key: String,
    enc_private_key: String,
    sign_public_key: String,
    sign_private_key: String,
    baseUrl: String,
}

#[derive(Deserialize)]
struct ChallengeResponse {
    data: ChallengeData,
}

#[derive(Deserialize)]
struct ChallengeData {
    challenge: String,
}

#[derive(Serialize)]
struct ChallengeRequest {
    publicKey: String,
}

#[derive(Serialize)]
struct AuthRequest {
    signature: String,
    publicKey: String,
}

#[derive(Deserialize)]
struct AuthResponse {
    data: AuthData,
}

#[derive(Deserialize)]
struct AuthData {
    token: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Init { config } => {
            init_command(config)?;
        }
        Commands::Auth { envname } => {
            auth_command(envname)?;
        }
    }

    Ok(())
}

fn init_command(config: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Decode the base64 encoded config string
    let decoded = base64::decode(config)?;
    let config_str = String::from_utf8(decoded)?;

    // Deserialize the config string to the Config struct
    let config: Config = serde_json::from_str(&config_str)?;

    // Decode the base64 encoded values
    let enc_public_key = base64::decode(&config.enc_public_key)?;
    let enc_private_key = base64::decode(&config.enc_private_key)?;
    let sign_public_key = base64::decode(&config.sign_public_key)?;
    let sign_private_key = base64::decode(&config.sign_private_key)?;

    // Get the .osvauld directory in the home directory
    let home_dir = home_dir().ok_or("Could not find home directory")?;
    let osvauld_dir = home_dir.join(".osvauld");
    fs::create_dir_all(&osvauld_dir)?;

    // Save the keys and baseUrl to files
    save_to_file(&osvauld_dir, "enc_public_key.asc", &enc_public_key)?;
    save_to_file(&osvauld_dir, "enc_private_key.asc", &enc_private_key)?;
    save_to_file(&osvauld_dir, "sign_public_key.asc", &sign_public_key)?;
    save_to_file(&osvauld_dir, "sign_private_key.asc", &sign_private_key)?;
    save_to_file(&osvauld_dir, "baseUrl.txt", config.baseUrl.as_bytes())?;

    println!("Configuration saved to ~/.osvauld");

    Ok(())
}

fn auth_command(envname: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Load the configuration files
    let home_dir = home_dir().ok_or("Could not find home directory")?;
    let osvauld_dir = home_dir.join(".osvauld");

    let base_url = fs::read_to_string(osvauld_dir.join("baseUrl.txt"))?;
    let sign_public_key = fs::read(osvauld_dir.join("sign_public_key.asc"))?;
    let sign_private_key = fs::read(osvauld_dir.join("sign_private_key.asc"))?;

    let sign_public_key_base64 = encode(&sign_public_key);

    // Create the challenge
    let client = Client::new();
    let challenge_response: ChallengeResponse = client
        .post(format!("{}/user/challenge", base_url))
        .json(&ChallengeRequest {
            publicKey: sign_public_key_base64.clone(),
        })
        .send()?
        .json()?;

    let challenge = challenge_response.data.challenge;

    // Sign the challenge
    let cert = openpgp::Cert::from_reader(&*sign_private_key)?;
    let key_pair = cert
        .keys()
        .unencrypted_secret()
        .with_policy(&openpgp::policy::StandardPolicy::new(), None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .ok_or("No signing key found")?
        .key()
        .clone()
        .into_keypair()?;

    let signed_challenge_base64 = sign_message_with_keypair(&challenge, key_pair)?;

    // Send the signed challenge to verify
    let auth_response: AuthResponse = client
        .post(format!("{}/user/verify", base_url))
        .json(&AuthRequest {
            signature: signed_challenge_base64,
            publicKey: sign_public_key_base64,
        })
        .send()?
        .json()?;

    println!("JWT Token: {}", auth_response.data.token);

    Ok(())
}

fn save_to_file(
    dir: &PathBuf,
    filename: &str,
    content: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let file_path = dir.join(filename);
    let mut file = File::create(file_path)?;
    file.write_all(content)?;
    Ok(())
}

pub fn sign_message_with_keypair(message: &str, keypair: KeyPair) -> Result<String, String> {
    let mut signed_message = Vec::new();
    let message_writer = Message::new(&mut signed_message);

    let mut signer = Signer::new(message_writer, keypair)
        .detached()
        .build()
        .map_err(|e| e.to_string())?;

    signer
        .write_all(message.as_bytes())
        .map_err(|_| "Failed to write message to signer.")?;
    signer
        .finalize()
        .map_err(|_| "Failed to finalize signer.")?;

    let mut armored_signature = Vec::new();
    let mut armor_writer =
        openpgp::armor::Writer::new(&mut armored_signature, openpgp::armor::Kind::Signature)
            .map_err(|e| e.to_string())?;

    armor_writer
        .write_all(&signed_message)
        .map_err(|_| "Failed to write signature.")?;
    armor_writer
        .finalize()
        .map_err(|_| "Failed to finalize armored writer.")?;

    let base64_encoded_signature = base64::encode(armored_signature);
    Ok(base64_encoded_signature)
}
