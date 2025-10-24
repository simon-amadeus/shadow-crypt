use crate::errors::{WorkflowError, WorkflowResult};
use clap::{Arg, Command};

/// Encryption CLI arguments structure
#[derive(Debug, Clone)]
pub struct DecryptionCliArgs {
    pub input_files: Vec<String>,
}

/// Parse encryption command line arguments
pub fn get_cli_args(args: Vec<String>) -> WorkflowResult<DecryptionCliArgs> {
    let cmd = || {
        Command::new("shadow").about("Decrypt shadow files").arg(
            Arg::new("files")
                .help("Input files to decrypt")
                .required(false)
                .num_args(1..)
                .value_name("FILE"),
        )
    };
    let matches = cmd()
        .try_get_matches_from(&args)
        .map_err(|e| WorkflowError::UserInput(e.to_string()))?;
    let input_files: Vec<String> = matches
        .get_many::<String>("files")
        .unwrap_or_default()
        .map(|s| s.to_string())
        .collect();

    if input_files.is_empty() {
        cmd().print_help().unwrap();
        // early exit for convenience
        std::process::exit(1);
    }

    Ok(DecryptionCliArgs { input_files })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_parse_cli_args_with_test_mode() {
        let args = vec!["shadow".to_string(), "file1.txt".to_string()];
        let cli_args = get_cli_args(args).unwrap();
        assert_eq!(cli_args.input_files, vec!["file1.txt".to_string()]);
    }

    #[test]
    fn test_parse_cli_args_no_files() {
        let args = vec!["shadow".to_string()];
        let result = get_cli_args(args);
        assert!(result.is_err());
        if let Err(WorkflowError::UserInput(_)) = result {
            // CLI error
        } else {
            panic!("Expected CLI error");
        }
    }
}
