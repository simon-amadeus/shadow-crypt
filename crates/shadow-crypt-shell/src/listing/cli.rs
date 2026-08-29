use std::path::PathBuf;

use clap::{Parser, error::ErrorKind};

use crate::errors::WorkflowError;

/// Listing CLI arguments structure
#[derive(Debug, Clone, Default, Parser)]
#[command(
    name = "shadows",
    about = "List shadow files in a directory",
    version,
    after_help = "Without --names, no password is needed and only the plaintext header \
                  metadata is shown. With --names, the original filenames are decrypted, \
                  which runs the full key derivation for every file."
)]
pub struct ListingCliArgs {
    /// Directory to list (defaults to the current directory)
    #[arg(value_name = "DIR")]
    pub dir: Option<PathBuf>,

    /// Decrypt and show the original filenames (prompts for the password)
    #[arg(long = "names", short = 'n')]
    pub names: bool,

    /// Read the password from this file instead of prompting (implies --names)
    #[arg(long = "password-file", value_name = "FILE")]
    pub password_file: Option<PathBuf>,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults_to_no_names_and_no_dir() {
        let args = get_cli_args(vec!["shadows".to_string()]).unwrap();
        assert!(!args.names);
        assert!(args.dir.is_none());
    }

    #[test]
    fn test_parses_dir_and_names() {
        let args = get_cli_args(vec![
            "shadows".to_string(),
            "--names".to_string(),
            "/some/dir".to_string(),
        ])
        .unwrap();
        assert!(args.names);
        assert_eq!(args.dir, Some(PathBuf::from("/some/dir")));
    }
}
