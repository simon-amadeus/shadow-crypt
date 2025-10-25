use crate::errors::{WorkflowError, WorkflowResult};
use clap::Parser;

/// Decryption CLI arguments structure
#[derive(Debug, Clone, Parser)]
#[command(name = "unshadow", about = "Decrypt shadow files", version)]
pub struct DecryptionCliArgs {
    /// Input files to decrypt
    #[arg(value_name = "FILE")]
    pub input_files: Vec<String>,
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
