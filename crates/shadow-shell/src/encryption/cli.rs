// shadow-shell/src/encryption/cli.rs
// CLI argument parsing for encryption operations
// Side effects: parses command line arguments

use clap::{Arg, ArgMatches, Command};
use shadow_core::encryption::input::{EncryptableFile, ValidEncryptionArgs};
use std::path::PathBuf;

use crate::errors::{WorkflowError, WorkflowResult};

/// Encryption CLI arguments structure
#[derive(Debug, Clone)]
pub struct CliArgs {
    pub input_files: Vec<String>,
    pub weak_password: bool,
}

/// Parse encryption command line arguments
/// Side effect: reads from command line
pub fn parse_cli_args() -> WorkflowResult<CliArgs> {
    let matches = Command::new("shadow")
        .about("Encrypt files using Shadow format")
        .arg(
            Arg::new("files")
                .help("Input files to encrypt")
                .required(true)
                .num_args(1..)
                .value_name("FILE"),
        )
        .arg(
            Arg::new("weak_password")
                .long("weak-password")
                .short('w')
                .help("Allow weak password (skip strength validation)")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    Ok(CliArgs::from_matches(&matches)?)
}

/// Parse CLI arguments from custom matches (for testing)
/// Pure function - no side effects
pub fn parse_args_from_matches(matches: &ArgMatches) -> WorkflowResult<CliArgs> {
    CliArgs::from_matches(matches)
}

impl CliArgs {
    /// Create EncryptionArgs from ArgMatches
    /// Pure function - no side effects
    fn from_matches(matches: &ArgMatches) -> WorkflowResult<CliArgs> {
        let input_files: Vec<String> = matches
            .get_many::<String>("files")
            .unwrap_or_default()
            .map(|s| s.to_string())
            .collect();

        if input_files.is_empty() {
            let msg = "No input files specified";
            return Err(WorkflowError::Password(msg.to_string()));
        }

        Ok(CliArgs {
            input_files,
            weak_password: matches.get_flag("weak_password"),
        })
    }
}

pub fn validate_input(input: CliArgs) -> WorkflowResult<ValidEncryptionArgs> {
    let mut files = Vec::new();

    if input.input_files.is_empty() {
        return Err(WorkflowError::NoFilesProvided);
    }

    for file_str in input.input_files {
        let path = PathBuf::from(file_str);
        if !path.exists() {
            return Err(WorkflowError::FileNotFound(path));
        }
        if !path.is_file() {
            return Err(WorkflowError::NotAFile(path));
        }
        files.push(EncryptableFile { path });
    }

    Ok(ValidEncryptionArgs {
        files,
        weak_password: input.weak_password,
    })
}
