mod api;
mod crypto;
mod utils;

use std::env;

use api::{fetch_challenge, get_environment_by_name, verify_challenge};
use clap::{Parser, Subcommand};
use crypto::sign_challenge_with_key;
use utils::{init_command, load_config_files};

use crate::crypto::{decrypt_message, get_key_pair};

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

fn auth_command(envname: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Load the configuration files
    let config = load_config_files()?;

    // Create the challenge
    let challenge = fetch_challenge(&config.base_url, &config.sign_public_key)?;

    // Sign the challenge
    let signed_challenge_base64 = sign_challenge_with_key(&challenge, &config.sign_private_key)?;

    // Send the signed challenge to verify
    let token = verify_challenge(
        &config.base_url,
        &signed_challenge_base64,
        &config.sign_public_key,
    )?;

    let env_data = get_environment_by_name(&config.base_url, envname, &token)?;

    println!("{:#?}", env_data);
    // Loop through each entry and decrypt the fieldValue
    let cert = get_key_pair(&config.enc_private_key)?;
    println!("Certificate: {:#?}", cert); // Print the certificate

    for entry in env_data {
        let decrypted_value = decrypt_message(&cert, &entry.fieldValue)?;
        // println!("Decrypted Value: {}", decrypted_value);
    }

    Ok(())
}
