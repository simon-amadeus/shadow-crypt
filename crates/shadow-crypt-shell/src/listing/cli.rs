use std::path::PathBuf;

use clap::{Parser, error::ErrorKind};

use crate::errors::WorkflowError;

/// Listing CLI arguments structure
#[derive(Debug, Clone, Default, Parser)]
#[command(
    name = "shadows",
    about = "List shadow files in a directory",
    version,
    after_help = "By default the original filenames are decrypted (prompts for the \
                  password and runs the full key derivation for every file); files the \
                  password does not open are still listed by their obfuscated names. \
                  With --no-names, no password is needed and only the plaintext header \
                  metadata is shown."
)]
pub struct ListingCliArgs {
    /// Directory to list (defaults to the current directory)
    #[arg(value_name = "DIR")]
    pub dir: Option<PathBuf>,

    /// Skip filename decryption; list plaintext header metadata only (no password needed)
    #[arg(long = "no-names", conflicts_with = "password_file")]
    pub no_names: bool,

    /// Read the password from this file instead of prompting
    #[arg(long = "password-file", value_name = "FILE")]
    pub password_file: Option<PathBuf>,

    /// Print the listing as JSON (original_filename is null when not decrypted)
    #[arg(long = "json")]
    pub json: bool,
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
    fn test_defaults_to_names_and_no_dir() {
        let args = get_cli_args(vec!["shadows".to_string()]).unwrap();
        assert!(!args.no_names);
        assert!(args.dir.is_none());
    }

    #[test]
    fn test_parses_dir_and_no_names() {
        let args = get_cli_args(vec![
            "shadows".to_string(),
            "--no-names".to_string(),
            "/some/dir".to_string(),
        ])
        .unwrap();
        assert!(args.no_names);
        assert_eq!(args.dir, Some(PathBuf::from("/some/dir")));
    }

    #[test]
    fn test_no_names_conflicts_with_password_file() {
        let result = get_cli_args(vec![
            "shadows".to_string(),
            "--no-names".to_string(),
            "--password-file".to_string(),
            "pw.txt".to_string(),
        ]);
        assert!(result.is_err());
    }
}
