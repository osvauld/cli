use base64::{decode, encode};
use dirs::home_dir;
use openpgp::cert::prelude::*;
use openpgp::crypto::KeyPair;
use openpgp::parse::Parse;
use openpgp::serialize::stream::*;
use reqwest::blocking::Client;
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
#[derive(Deserialize)]
pub struct Config {
    pub enc_public_key: String,
    pub enc_private_key: String,
    pub sign_public_key: String,
    pub sign_private_key: String,
    pub base_url: String,
}

#[derive(Deserialize)]
struct ChallengeResponse {
    data: ChallengeData,
}

#[derive(Deserialize)]
struct ChallengeData {
    challenge: String,
}

#[derive(Serialize, Debug)]
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

#[derive(Deserialize, Debug)]
struct GetEnvironmentFieldsByNameRow {
    id: String,
    fieldName: String,
    fieldValue: String,
    credentialId: String,
}

#[derive(Deserialize)]
struct GetEnvApiResponse {
    data: Vec<GetEnvironmentFieldsByNameRow>,
}

pub fn get_environment_by_name(
    base_url: &str,
    env_name: &str,
    jwt_token: &str,
) -> Result<Vec<GetEnvironmentFieldsByNameRow>, Box<dyn Error>> {
    let client = Client::new();
    let url = format!("{}/environment/{}", base_url, env_name);

    let response: GetEnvApiResponse = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt_token))
        .send()?
        .json()?;

    Ok(response.data)
}

pub fn save_to_file(
    dir: &PathBuf,
    filename: &str,
    content: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let file_path = dir.join(filename);
    let mut file = File::create(file_path)?;
    file.write_all(content)?;
    Ok(())
}

pub fn load_config_files() -> Result<Config, Box<dyn std::error::Error>> {
    let home_dir = home_dir().ok_or("Could not find home directory")?;
    let osvauld_dir = home_dir.join(".osvauld");

    let base_url = fs::read_to_string(osvauld_dir.join("baseUrl.txt"))?;
    let sign_public_key = fs::read(osvauld_dir.join("sign_public_key.asc"))?;
    let sign_private_key = fs::read(osvauld_dir.join("sign_private_key.asc"))?;

    let config = Config {
        enc_public_key: base_url.clone(),
        enc_private_key: base_url.clone(),
        sign_public_key: encode(sign_public_key),
        sign_private_key: encode(sign_private_key),
        base_url: base_url,
    };

    Ok(config)
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

pub fn fetch_challenge(
    base_url: &str,
    public_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::new();
    let request_body = ChallengeRequest {
        publicKey: public_key.to_string(),
    };

    println!(
        "Debug: Sending challenge request with body: {:?}",
        &request_body
    );

    let challenge_response: ChallengeResponse = client
        .post(format!("{}/user/challenge", base_url))
        .json(&request_body)
        .send()?
        .json()?;

    Ok(challenge_response.data.challenge)
}
pub fn verify_challenge(
    base_url: &str,
    signed_challenge: &str,
    public_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::new();
    let auth_response: AuthResponse = client
        .post(format!("{}/user/verify", base_url))
        .json(&AuthRequest {
            signature: signed_challenge.to_string(),
            publicKey: public_key.to_string(),
        })
        .send()?
        .json()?;

    Ok(auth_response.data.token)
}

pub fn init_command(config: &str) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn auth_command(envname: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Load the configuration files
    let config = load_config_files()?;

    // Create the challenge
    let challenge = fetch_challenge(&config.base_url, &config.sign_public_key)?;

    // Sign the challenge
    let cert = openpgp::Cert::from_reader(&*decode(&config.sign_private_key)?)?;
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
    let token = verify_challenge(
        &config.base_url,
        &signed_challenge_base64,
        &config.sign_public_key,
    )?;

    let env_data = get_environment_by_name(&config.base_url, envname, &token)?;

    println!("JWT Token: {:?}", env_data);

    Ok(())
}
