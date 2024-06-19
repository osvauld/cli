mod api;
mod crypto;
mod utils;
use api::{fetch_challenge, get_environment_by_name, verify_challenge};
use clap::{Parser, Subcommand};

use crate::crypto::{decrypt_message, get_key_pair};
use crypto::sign_challenge_with_key;
use dirs::home_dir;
use log::{error, info};
use simplelog::*;
use std::env;
use std::error::Error;
use std::fs::File;
use std::process::Command as ProcessCommand;
use utils::{init_command, load_config_files};

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
    let mut log_path = home_dir().expect("Could not get home directory");
    log_path.push(".osvauld");
    std::fs::create_dir_all(&log_path).expect("Failed to create .osvauld directory");
    log_path.push("log.txt");
    let log_file = File::create(log_path).expect("Failed to create log file");

    CombinedLogger::init(vec![WriteLogger::new(
        LevelFilter::Info,
        Config::default(),
        log_file,
    )])
    .unwrap();
    match opt.cmd {
        Command::Init { base64string } => {
            println!("Init with base64 string: {}", base64string);
            match init_command(&base64string) {
                Ok(_) => info!("Init command successful"),
                Err(e) => error!("Error running init command: {}", e),
            }
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
            match auth_command(&envname, &command, &command_args_refs) {
                Ok(_) => info!("Auth command successful"),
                Err(e) => error!("Error running auth command: {}", e),
            }
        }
    }
}
