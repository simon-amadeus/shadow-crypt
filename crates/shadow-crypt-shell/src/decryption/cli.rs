use std::path::PathBuf;

use crate::errors::{WorkflowError, WorkflowResult};
use clap::Parser;

/// Decryption CLI arguments structure
#[derive(Debug, Clone, Default, Parser)]
#[command(
    name = "unshadow",
    about = "Decrypt shadow files",
    version,
    after_help = "Exit codes: 0 success; 1 operation failed; 2 invalid usage or input; \
                  3 authentication failure (wrong password or corrupted file)."
)]
pub struct DecryptionCliArgs {
    /// Input files to decrypt
    #[arg(value_name = "FILE")]
    pub input_files: Vec<String>,

    /// Write decrypted files to this directory (created if missing; defaults to the current directory)
    #[arg(long = "output-dir", short = 'o', value_name = "DIR")]
    pub output_dir: Option<PathBuf>,

    /// Read the password from this file instead of prompting (one trailing newline is ignored)
    #[arg(long = "password-file", value_name = "FILE")]
    pub password_file: Option<PathBuf>,

    /// Overwrite existing output files instead of failing
    #[arg(long = "force", short = 'f')]
    pub force: bool,

    /// Suppress progress and per-file success output (errors are still shown)
    #[arg(long = "quiet", short = 'q')]
    pub quiet: bool,
}

/// Parse decryption command line arguments
pub fn get_cli_args(args: Vec<String>) -> WorkflowResult<DecryptionCliArgs> {
    let cli_args = DecryptionCliArgs::try_parse_from(args).map_err(|e| {
        // If it's help or version, it's not a user input error
        if e.kind() == clap::error::ErrorKind::DisplayHelp
            || e.kind() == clap::error::ErrorKind::DisplayVersion
        {
            // Print the message and exit successfully
            eprintln!("{}", e);
            std::process::exit(0);
        }
        WorkflowError::UserInput(e.to_string())
    })?;

    if cli_args.input_files.is_empty() {
        return Err(WorkflowError::UserInput(
            "No input files provided".to_string(),
        ));
    }

    Ok(cli_args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cli_args_with_files() {
        let args = vec![
            "unshadow".to_string(),
            "file1.txt".to_string(),
            "file2.txt".to_string(),
        ];
        let cli_args = get_cli_args(args).unwrap();
        assert_eq!(
            cli_args.input_files,
            vec!["file1.txt".to_string(), "file2.txt".to_string()]
        );
    }

    #[test]
    fn test_parse_cli_args_with_single_file() {
        let args = vec!["unshadow".to_string(), "file1.txt".to_string()];
        let cli_args = get_cli_args(args).unwrap();
        assert_eq!(cli_args.input_files, vec!["file1.txt".to_string()]);
    }

    #[test]
    fn test_parse_cli_args_no_files() {
        let args = vec!["unshadow".to_string()];
        let result = get_cli_args(args);
        assert!(result.is_err());
        if let Err(WorkflowError::UserInput(msg)) = result {
            assert_eq!(msg, "No input files provided");
        } else {
            panic!("Expected UserInput error");
        }
    }

    #[test]
    fn test_parse_cli_args_help() {
        // Note: --help now causes the function to exit successfully, so this test is removed
    }
}
