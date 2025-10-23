use clap::{Arg, ArgMatches, Command};
use shadow_core::profile::SecurityProfile;

use crate::errors::{WorkflowError, WorkflowResult};

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

pub fn get_security_profile(test_mode: bool) -> SecurityProfile {
    if test_mode {
        SecurityProfile::Test
    } else {
        SecurityProfile::Production
    }
}
