mod api;
mod crypto;
mod utils;
use api::{fetch_challenge, get_environment_by_name, verify_challenge};
use clap::{Parser, Subcommand};

use crypto::sign_challenge_with_key;
use std::env;
use std::error::Error;
use std::process::Command as ProcessCommand;
use utils::{init_command, load_config_files};

use crate::crypto::{decrypt_message, get_key_pair};

fn auth_command(
    envname: &str,
    command: &str,
    command_args: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
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

    let cert = get_key_pair(&config.enc_private_key)?;

    for entry in env_data {
        let decrypted_value = decrypt_message(&cert, &entry.fieldValue)?;
        env::set_var(&entry.fieldName, decrypted_value);
    }
    let status = ProcessCommand::new(command).args(command_args).status()?;

    if !status.success() {
        eprintln!("Command executed with failing error code");
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}

#[derive(Parser, Debug)]
#[command(name = "osvauld")]
#[command(about = "CLI tool for Osvauld", version = "1.0")]
struct Opt {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Init {
        #[arg(help = "Base64 encoded string")]
        base64string: String,
    },
    Env {
        #[arg(help = "Environment name")]
        envname: String,
        #[arg(help = "Command to run")]
        command: String,
        #[arg(help = "Arguments for the command")]
        command_args: Vec<String>,
    },
}

fn main() {
    let opt = Opt::parse();

    match opt.cmd {
        Command::Init { base64string } => {
            println!("Init with base64 string: {}", base64string);
            let _ = init_command(&base64string);
        }
        Command::Env {
            envname,
            command,
            command_args,
        } => {
            println!(
                "Env with name: {}, command: {}, args: {:?}",
                envname, command, command_args
            );
            // Convert Vec<String> to Vec<&str>
            let command_args_refs: Vec<&str> = command_args.iter().map(|s| &**s).collect();
            // Call auth_command with the correct type
            let _ = auth_command(&envname, &command, &command_args_refs);
        }
    }
}
