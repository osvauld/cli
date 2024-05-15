mod utils;

use clap::{Parser, Subcommand};
use utils::{auth_command, init_command};

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
