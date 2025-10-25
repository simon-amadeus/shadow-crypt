use clap::{Arg, Command};
use shadow_crypt_core::profile::SecurityProfile;

use crate::errors::{WorkflowError, WorkflowResult};

/// Encryption CLI arguments structure
#[derive(Debug, Clone)]
pub struct CliArgs {
    pub input_files: Vec<String>,
    pub test_mode: bool, // If true, use SecurityProfile::Test
}

/// Parse encryption command line arguments
pub fn get_cli_args(args: Vec<String>) -> WorkflowResult<CliArgs> {
    let cmd = || {
        Command::new("shadow")
        .about("Encrypt files using shadow format")
        .arg(
            Arg::new("files")
                .help("Input files to encrypt")
                .required(false)
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
        return Err(WorkflowError::UserInput(
            "No input files provided".to_string(),
        ));
    }

    Ok(CliArgs {
        input_files,
        test_mode: matches.get_flag("test_mode"),
    })
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
