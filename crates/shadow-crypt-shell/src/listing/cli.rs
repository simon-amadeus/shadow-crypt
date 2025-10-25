use clap::{Parser, error::ErrorKind};

use crate::errors::WorkflowError;

/// Listing CLI arguments structure
#[derive(Debug, Clone, Parser)]
#[command(
    name = "shadows",
    about = "List shadow files in the current directory",
    version
)]
pub struct ListingCliArgs {}

/// Parse listing command line arguments
pub fn get_cli_args(args: Vec<String>) -> Result<ListingCliArgs, WorkflowError> {
    ListingCliArgs::try_parse_from(args).map_err(|e| {
        // If it's help or version, it's not a user input error
        if e.kind() == ErrorKind::DisplayHelp || e.kind() == ErrorKind::DisplayVersion {
            // Print the message and exit successfully
            eprintln!("{}", e);
            std::process::exit(0);
        }
        WorkflowError::UserInput(e.to_string())
    })
}
