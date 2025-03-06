use clap::{Parser, Subcommand};

mod client;
mod server;

use crate::client::Downloader;
use crate::server::server;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[derive(Parser)]
struct Cmd {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Client supporting resumable and concurrent download
    Client {
        #[arg(short, long)]
        url: String,

        /// file name to save
        #[arg(short, long)]
        filename: String,
    },

    /// Server supporting concurrent download and upload
    Server {
        /// Ip and Port server should listen to: example: 0.0.0.0:8000
        #[arg(short, long)]
        address: String,
    },
}

#[tokio::main]
async fn main() {
    let cmd = Cmd::parse();
    let cpus = num_cpus::get();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    match &cmd.command {
        Commands::Client { url, filename } => {
            let mut downloader = Downloader::new(3, 30);
            match downloader.download_file(url, filename, cpus).await {
                Ok(_) => println!("File downloaded successfully."),
                Err(e) => eprintln!("Error downloading file: {}", e),
            }
        }
        Commands::Server { address } => match server(address).await {
            Ok(_) => (),
            Err(e) => println!("Server Error: {e}"),
        },
    }
}
