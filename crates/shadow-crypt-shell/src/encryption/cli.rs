use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use shadow_crypt_core::profile::SecurityProfile;

use crate::errors::{WorkflowError, WorkflowResult};

/// The security profile as selected on the command line. Run with
/// `--profiles` for each profile's key derivation parameters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum CliProfile {
    /// OWASP-recommended key derivation (the default)
    #[default]
    Standard,
    /// Maximum-cost key derivation; needs 1 GiB of free RAM per file
    Paranoid,
    /// For automated testing only — insecure, skips password strength checks
    Test,
}

impl From<CliProfile> for SecurityProfile {
    fn from(profile: CliProfile) -> Self {
        match profile {
            CliProfile::Standard => SecurityProfile::Standard,
            CliProfile::Paranoid => SecurityProfile::Paranoid,
            CliProfile::Test => SecurityProfile::Test,
        }
    }
}

/// Encryption CLI arguments structure
#[derive(Debug, Clone, Default, Parser)]
#[command(
    name = "shadow",
    about = "Encrypt files using shadow format",
    version,
    after_help = "A directory input becomes a single encrypted archive that hides the file \
                  count, names, and sizes inside it. With --recursive, the directory's \
                  files are instead encrypted individually (sync-friendly: one .shadow \
                  per file), preserving their relative paths.\n\n\
                  Run with --profiles to see each security profile's key derivation \
                  parameters.\n\n\
                  Exit codes: 0 success; 1 operation failed; 2 invalid usage or input; \
                  3 authentication failure (wrong password or corrupted file)."
)]
pub struct EncryptionCliArgs {
    /// Input files or directories to encrypt
    #[arg(value_name = "PATH")]
    pub input_files: Vec<String>,

    /// Encrypt a directory's files individually instead of as one archive
    #[arg(long = "recursive", short = 'r')]
    pub recursive: bool,

    /// Security profile controlling the key derivation cost
    #[arg(long = "profile", value_enum, default_value_t = CliProfile::Standard)]
    pub profile: CliProfile,

    /// Print the available security profiles and their parameters, then exit
    #[arg(long = "profiles")]
    pub list_profiles: bool,

    /// Write encrypted files to this directory (created if missing; defaults to the current directory)
    #[arg(long = "output-dir", short = 'o', value_name = "DIR")]
    pub output_dir: Option<PathBuf>,

    /// Read the password from this file instead of prompting (one trailing newline is ignored)
    #[arg(long = "password-file", value_name = "FILE")]
    pub password_file: Option<PathBuf>,

    /// Suppress progress and per-file success output (errors are still shown)
    #[arg(long = "quiet", short = 'q')]
    pub quiet: bool,

    /// Delete originals after successful encryption. Best-effort removal:
    /// on SSDs and journaling filesystems the data may remain recoverable
    /// until overwritten. With --recursive, emptied directories are kept.
    #[arg(long = "delete")]
    pub delete: bool,
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

    if !cli_args.list_profiles && cli_args.input_files.is_empty() {
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
    fn test_profile_defaults_to_standard() {
        let args = get_cli_args(vec!["shadow".to_string(), "file1.txt".to_string()]).unwrap();
        assert_eq!(args.profile, CliProfile::Standard);
        assert_eq!(
            SecurityProfile::from(args.profile),
            SecurityProfile::Standard
        );
    }

    #[test]
    fn test_profile_parses_all_levels() {
        for (name, expected) in [
            ("standard", SecurityProfile::Standard),
            ("paranoid", SecurityProfile::Paranoid),
            ("test", SecurityProfile::Test),
        ] {
            let args = get_cli_args(vec![
                "shadow".to_string(),
                "--profile".to_string(),
                name.to_string(),
                "file1.txt".to_string(),
            ])
            .unwrap();
            assert_eq!(SecurityProfile::from(args.profile), expected);
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

    #[test]
    fn test_profiles_flag_needs_no_input_files() {
        let args = get_cli_args(vec!["shadow".to_string(), "--profiles".to_string()]).unwrap();
        assert!(args.list_profiles);
        assert!(args.input_files.is_empty());
    }
}
