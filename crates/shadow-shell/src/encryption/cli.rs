// shadow-shell/src/encryption/cli.rs
// CLI argument parsing for encryption operations
// Side effects: parses command line arguments

use clap::{Arg, ArgMatches, Command};
use std::path::PathBuf;

use crate::errors::ApplicationError;

/// Encryption CLI arguments structure
#[derive(Debug, Clone)]
pub struct EncryptionArgs {
    pub input_files: Vec<String>,
    pub quiet: bool,
    pub weak_password: bool,
}

/// Parse encryption command line arguments
/// Side effect: reads from command line
pub fn parse_args() -> Result<EncryptionArgs, ApplicationError> {
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

    Ok(EncryptionArgs::from_matches(&matches)?)
}

/// Parse CLI arguments from custom matches (for testing)
/// Pure function - no side effects
pub fn parse_args_from_matches(matches: &ArgMatches) -> Result<EncryptionArgs, ApplicationError> {
    EncryptionArgs::from_matches(matches)
}

impl EncryptionArgs {
    /// Create EncryptionArgs from ArgMatches
    /// Pure function - no side effects
    fn from_matches(matches: &ArgMatches) -> Result<Self, ApplicationError> {
        let input_files: Vec<String> = matches
            .get_many::<String>("files")
            .unwrap_or_default()
            .map(|s| s.to_string())
            .collect();

        if input_files.is_empty() {
            let msg = "No input files specified";
            return Err(ApplicationError::Password(msg.to_string()));
        }

        Ok(EncryptionArgs {
            input_files,
            quiet: matches.get_flag("quiet"),
            weak_password: matches.get_flag("weak_password"),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptableFile {
    pub path: PathBuf,
}

pub struct ValidEncryptionInput {
    pub files: Vec<EncryptableFile>,
    pub quiet: bool,
    pub weak_password: bool,
}

pub fn validate_input(input: EncryptionArgs) -> Result<ValidEncryptionInput, ApplicationError> {
    let mut files = Vec::new();

    if input.input_files.is_empty() {
        return Err(ApplicationError::NoFilesProvided);
    }

    for file_str in input.input_files {
        let path = PathBuf::from(file_str);
        if !path.exists() {
            return Err(ApplicationError::FileNotFound(path));
        }
        if !path.is_file() {
            return Err(ApplicationError::NotAFile(path));
        }
        files.push(EncryptableFile { path });
    }

    Ok(ValidEncryptionInput {
        files,
        quiet: input.quiet,
        weak_password: input.weak_password,
    })
}
