// shadow-encryption-shell/src/cli.rs
// CLI argument parsing for encryption operations
// Side effects: parses command line arguments

use clap::{Arg, ArgMatches, Command};
use std::path::PathBuf;

/// Encryption CLI arguments structure
#[derive(Debug, Clone)]
pub struct EncryptionArgs {
    pub input_files: Vec<PathBuf>,
    pub obfuscate: bool,
    pub force: bool,
    pub keep: bool,
    pub quiet: bool,
}

/// Parse encryption command line arguments
/// Side effect: reads from command line
pub fn parse_args() -> Result<EncryptionArgs, Box<dyn std::error::Error>> {
    let matches = Command::new("shadow")
        .about("Encrypt files using Shadow format")
        .arg(
            Arg::new("files")
                .help("Input files to encrypt")
                .required(true)
                .num_args(1..)
                .value_name("FILE")
        )
        .arg(
            Arg::new("obfuscate")
                .long("obfuscate")
                .short('o')
                .help("Obfuscate filenames (generate random names)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("force")
                .long("force")
                .short('f')
                .help("Overwrite existing output files")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("keep")
                .long("keep")
                .short('k')
                .help("Keep original files after encryption")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("quiet")
                .long("quiet")
                .short('q')
                .help("Suppress progress output")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();

    Ok(EncryptionArgs::from_matches(&matches)?)
}

/// Parse CLI arguments from custom matches (for testing)
/// Pure function - no side effects
pub fn parse_args_from_matches(matches: &ArgMatches) -> Result<EncryptionArgs, Box<dyn std::error::Error>> {
    EncryptionArgs::from_matches(matches)
}

impl EncryptionArgs {
    /// Create EncryptionArgs from ArgMatches
    /// Pure function - no side effects
    fn from_matches(matches: &ArgMatches) -> Result<Self, Box<dyn std::error::Error>> {
        let input_files: Vec<PathBuf> = matches
            .get_many::<String>("files")
            .unwrap_or_default()
            .map(PathBuf::from)
            .collect();

        if input_files.is_empty() {
            return Err("No input files specified".into());
        }

        Ok(EncryptionArgs {
            input_files,
            obfuscate: matches.get_flag("obfuscate"),
            force: matches.get_flag("force"),
            keep: matches.get_flag("keep"),
            quiet: matches.get_flag("quiet"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Command;

    fn create_test_app() -> Command {
        Command::new("shadow")
            .arg(
                Arg::new("files")
                    .help("Input files to encrypt")
                    .required(true)
                    .num_args(1..)
                    .value_name("FILE")
            )
            .arg(
                Arg::new("obfuscate")
                    .long("obfuscate")
                    .short('o')
                    .action(clap::ArgAction::SetTrue)
            )
            .arg(
                Arg::new("force")
                    .long("force")
                    .short('f')
                    .action(clap::ArgAction::SetTrue)
            )
            .arg(
                Arg::new("keep")
                    .long("keep")
                    .short('k')
                    .action(clap::ArgAction::SetTrue)
            )
            .arg(
                Arg::new("quiet")
                    .long("quiet")
                    .short('q')
                    .action(clap::ArgAction::SetTrue)
            )
    }

    #[test]
    fn test_parse_basic_args() {
        let app = create_test_app();
        let matches = app.try_get_matches_from(vec!["shadow", "test.txt"]).unwrap();
        let args = parse_args_from_matches(&matches).unwrap();

        assert_eq!(args.input_files.len(), 1);
        assert_eq!(args.input_files[0], PathBuf::from("test.txt"));
        assert!(!args.obfuscate);
        assert!(!args.force);
        assert!(!args.keep);
        assert!(!args.quiet);
    }

    #[test]
    fn test_parse_all_flags() {
        let app = create_test_app();
        let matches = app.try_get_matches_from(vec![
            "shadow", "test1.txt", "test2.txt", 
            "--obfuscate", "--force", "--keep", "--quiet"
        ]).unwrap();
        let args = parse_args_from_matches(&matches).unwrap();

        assert_eq!(args.input_files.len(), 2);
        assert!(args.obfuscate);
        assert!(args.force);
        assert!(args.keep);
        assert!(args.quiet);
    }

    #[test]
    fn test_parse_short_flags() {
        let app = create_test_app();
        let matches = app.try_get_matches_from(vec![
            "shadow", "test.txt", "-o", "-f", "-k", "-q"
        ]).unwrap();
        let args = parse_args_from_matches(&matches).unwrap();

        assert!(args.obfuscate);
        assert!(args.force);
        assert!(args.keep);
        assert!(args.quiet);
    }

    #[test]
    fn test_no_input_files_error() {
        let app = create_test_app();
        let result = app.try_get_matches_from(vec!["shadow"]);
        assert!(result.is_err());
    }
}