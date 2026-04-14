use clap::{Parser, Subcommand};

mod abi;
mod commands;
mod config;
mod contract;
mod crypto;
mod github;
mod output;
mod rpc;
mod tx;

#[derive(Parser)]
#[command(name = "pora")]
#[command(about = "Security audit market CLI. Audit. Earn. Forget.")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format: json (default) or text
    #[arg(long, global = true, default_value = "auto")]
    format: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage audit requests (requester commands)
    Request {
        #[command(subcommand)]
        action: commands::request::RequestAction,
    },
    /// Manage performer agent (performer commands)
    Performer {
        #[command(subcommand)]
        action: commands::performer::PerformerAction,
    },
    /// System diagnostics and configuration
    System {
        #[command(subcommand)]
        action: commands::system::SystemAction,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let is_tty = atty::is(atty::Stream::Stdout);
    let format = match cli.format.as_str() {
        "json" => output::Format::Json,
        "text" => output::Format::Text,
        _ => {
            if is_tty {
                output::Format::Text
            } else {
                output::Format::Json
            }
        }
    };

    let result = match cli.command {
        Commands::Request { action } => commands::request::run(action, &format).await,
        Commands::Performer { action } => commands::performer::run(action, &format).await,
        Commands::System { action } => commands::system::run(action, &format).await,
    };

    if let Err(e) = result {
        output::print_error(&format, &e);
        std::process::exit(1);
    }
}
