use crate::errors::{WorkflowError, WorkflowResult};
use clap::Command;

/// Decryption CLI arguments structure
#[derive(Debug, Clone)]
pub struct DecryptionCliArgs {
    pub input_files: Vec<String>,
}

/// Parse encryption command line arguments
pub fn get_cli_args(args: Vec<String>) -> WorkflowResult<DecryptionCliArgs> {
    let cmd = || Command::new("shadows").about("Show information about shadow files");
    let matches = cmd()
        .try_get_matches_from(&args)
        .map_err(|e| WorkflowError::UserInput(e.to_string()))?;
    let input_files: Vec<String> = matches
        .get_many::<String>("files")
        .unwrap_or_default()
        .map(|s| s.to_string())
        .collect();

    if input_files.is_empty() {
        return Err(WorkflowError::UserInput(
            "No input files provided".to_string(),
        ));
    }

    Ok(DecryptionCliArgs { input_files })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cli_args_help() {
        let args = vec!["shadows".to_string(), "--help".to_string()];
        let result = get_cli_args(args);
        assert!(result.is_err());
        // Clap handles --help by returning an error
    }
}
