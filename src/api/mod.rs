use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Deserialize, Debug)]
struct ChallengeResponse {
    data: ChallengeData,
}

#[derive(Deserialize, Debug)]
struct ChallengeData {
    challenge: String,
}

#[derive(Serialize, Debug)]
struct ChallengeRequest {
    publicKey: String,
}

#[derive(Serialize, Debug)]
struct AuthRequest {
    signature: String,
    publicKey: String,
}

#[derive(Deserialize, Debug)]
struct AuthResponse {
    data: AuthData,
}

#[derive(Deserialize, Debug)]
struct AuthData {
    token: String,
}

#[derive(Deserialize, Debug)]
pub struct GetEnvironmentFieldsByNameRow {
    id: String,
    pub fieldName: String,
    pub fieldValue: String,
    credentialId: String,
}

#[derive(Deserialize, Debug)]
struct GetEnvApiResponse {
    data: Vec<GetEnvironmentFieldsByNameRow>,
}

pub fn fetch_challenge(base_url: &str, public_key: &str) -> Result<String, Box<dyn Error>> {
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
) -> Result<String, Box<dyn Error>> {
    let client = Client::new();
    let request_body = AuthRequest {
        signature: signed_challenge.to_string(),
        publicKey: public_key.to_string(),
    };

    println!(
        "Debug: Sending verify request with body: {:?}",
        &request_body
    );

    let auth_response: AuthResponse = client
        .post(format!("{}/user/verify", base_url))
        .json(&request_body)
        .send()?
        .json()?;

    Ok(auth_response.data.token)
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
