use std::path::PathBuf;

use clap::Parser;
use shadow_crypt_core::profile::SecurityProfile;

use crate::errors::{WorkflowError, WorkflowResult};

/// Encryption CLI arguments structure
#[derive(Debug, Clone, Default, Parser)]
#[command(name = "shadow", about = "Encrypt files using shadow format", version)]
pub struct EncryptionCliArgs {
    /// Input files to encrypt
    #[arg(value_name = "FILE")]
    pub input_files: Vec<String>,

    /// Use test security profile for faster key derivation (not recommended for production)
    #[arg(long = "test-mode", short = 't')]
    pub test_mode: bool,

    /// Write encrypted files to this directory (created if missing; defaults to the current directory)
    #[arg(long = "output-dir", short = 'o', value_name = "DIR")]
    pub output_dir: Option<PathBuf>,

    /// Read the password from this file instead of prompting (one trailing newline is ignored)
    #[arg(long = "password-file", value_name = "FILE")]
    pub password_file: Option<PathBuf>,
}

/// Parse encryption command line arguments
pub fn get_cli_args(args: Vec<String>) -> WorkflowResult<EncryptionCliArgs> {
    let cli_args = EncryptionCliArgs::try_parse_from(args).map_err(|e| {
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

pub fn get_security_profile(test_mode: bool) -> SecurityProfile {
    if test_mode {
        SecurityProfile::Test
    } else {
        SecurityProfile::Production
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_security_profile_test_mode() {
        match get_security_profile(true) {
            SecurityProfile::Test => {}
            _ => panic!("Expected Test profile"),
        }
    }

    #[test]
    fn test_get_security_profile_production() {
        match get_security_profile(false) {
            SecurityProfile::Production => {}
            _ => panic!("Expected Production profile"),
        }
    }

    #[test]
    fn test_parse_cli_args_with_files() {
        let args = vec![
            "shadow".to_string(),
            "file1.txt".to_string(),
            "file2.txt".to_string(),
        ];
        let cli_args = get_cli_args(args).unwrap();
        assert_eq!(
            cli_args.input_files,
            vec!["file1.txt".to_string(), "file2.txt".to_string()]
        );
        assert!(!cli_args.test_mode);
    }

    #[test]
    fn test_parse_cli_args_with_test_mode() {
        let args = vec![
            "shadow".to_string(),
            "--test-mode".to_string(),
            "file1.txt".to_string(),
        ];
        let cli_args = get_cli_args(args).unwrap();
        assert_eq!(cli_args.input_files, vec!["file1.txt".to_string()]);
        assert!(cli_args.test_mode);
    }

    #[test]
    fn test_parse_cli_args_no_files() {
        let args = vec!["shadow".to_string()];
        let result = get_cli_args(args);
        assert!(result.is_err());
        if let Err(WorkflowError::UserInput(msg)) = result {
            assert_eq!(msg, "No input files provided");
        } else {
            panic!("Expected UserInput error");
        }
    }
}
