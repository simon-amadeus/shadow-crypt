// shadow-shell/src/encryption/cli.rs
// CLI argument parsing for encryption operations
// Side effects: parses command line arguments

use clap::{Arg, ArgMatches, Command};
use std::path::PathBuf;

use crate::{
    encryption::input::{InputFile, ValidEncryptionArgs},
    errors::{WorkflowError, WorkflowResult},
};

/// Encryption CLI arguments structure
#[derive(Debug, Clone)]
pub struct CliArgs {
    pub input_files: Vec<String>,
    pub test_mode: bool, // If true, use SecurityProfile::Test
}

/// Parse encryption command line arguments
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
            Arg::new("test_mode")
                .long("test-mode")
                .short('t')
                .help("Use test security profile for faster key derivation (not recommended for production)")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    CliArgs::from_matches(&matches)
}

impl CliArgs {
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
            test_mode: matches.get_flag("test_mode"),
        })
    }
}

pub fn validate_input(input: CliArgs) -> WorkflowResult<ValidEncryptionArgs> {
    let mut files = Vec::new();

    if input.input_files.is_empty() {
        return Err(WorkflowError::UserInput(
            "No input files provided".to_string(),
        ));
    }

    for file_str in input.input_files {
        let path = PathBuf::from(file_str);
        if !path.exists() {
            return Err(WorkflowError::UserInput(format!(
                "Input file does not exist: {}",
                path.display()
            )));
        }
        if !path.is_file() {
            return Err(WorkflowError::UserInput(format!(
                "Input path is not a file: {}",
                path.display()
            )));
        }
        let name: String = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                WorkflowError::UserInput(format!("Invalid filename for path: {}", path.display()))
            })?
            .to_string();
        let size: u64 = path
            .metadata()
            .map_err(|_| {
                WorkflowError::UserInput(format!(
                    "Unable to read metadata for file: {}",
                    path.display()
                ))
            })?
            .len();

        files.push(InputFile {
            path,
            filename: name,
            size,
        });
    }

    Ok(ValidEncryptionArgs {
        files,
        test_mode: input.test_mode,
    })
}
