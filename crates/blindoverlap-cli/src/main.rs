//! BlindOverlap CLI - placeholder for commit 5.

use clap::Parser;

#[derive(Parser)]
#[command(name = "blindoverlap")]
#[command(about = "Private set intersection over content-addressed fact IDs")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Encode JSON facts to fact IDs (placeholder)
    Encode,
    /// Run PSI intersection (placeholder)
    Intersect,
    /// Sign an intersection receipt (placeholder)
    ReceiptSign,
    /// Verify an intersection receipt (placeholder)
    ReceiptVerify,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Encode) => println!("encode: not yet implemented"),
        Some(Commands::Intersect) => println!("intersect: not yet implemented"),
        Some(Commands::ReceiptSign) => println!("receipt-sign: not yet implemented"),
        Some(Commands::ReceiptVerify) => println!("receipt-verify: not yet implemented"),
        None => println!("BlindOverlap v0.1.0 - use --help for commands"),
    }
}
