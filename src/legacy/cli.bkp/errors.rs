//! # CLI Error Handling
//! 
//! User-facing error presentation and exit code management for CLI commands.

use crate::application::errors::{ApplicationError, ErrorSeverity};
use std::fmt;
use std::process;

/// CLI-specific error handling and presentation
#[derive(Debug)]
pub struct CliError {
    /// The underlying application error
    error: ApplicationError,
    /// Command context where error occurred
    command: String,
    /// Exit code to use when terminating
    exit_code: i32,
}

/// Standard exit codes for CLI commands
pub mod exit_codes {
    /// Success
    pub const SUCCESS: i32 = 0;
    /// General error
    pub const GENERAL_ERROR: i32 = 1;
    /// Wrong password or authentication failure
    pub const AUTHENTICATION_ERROR: i32 = 2;
    /// File not found or access denied
    pub const FILE_ERROR: i32 = 3;
    /// Invalid input or arguments
    pub const INPUT_ERROR: i32 = 4;
    /// Security violation
    pub const SECURITY_ERROR: i32 = 5;
    /// Resource constraint (memory, disk space, etc.)
    pub const RESOURCE_ERROR: i32 = 6;
    /// Configuration error
    pub const CONFIG_ERROR: i32 = 7;
    /// User cancelled operation
    pub const USER_CANCELLED: i32 = 130; // Standard Ctrl+C exit code
}

impl CliError {
    /// Create a new CLI error with context
    pub fn new(error: ApplicationError, command: &str) -> Self {
        let exit_code = Self::determine_exit_code(&error);
        Self {
            error,
            command: command.to_string(),
            exit_code,
        }
    }

    /// Get the exit code for this error
    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }

    /// Get the command context
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Get the underlying application error
    pub fn error(&self) -> &ApplicationError {
        &self.error
    }

    /// Present error to user and exit the process
    pub fn present_and_exit(&self) -> ! {
        self.present_error();
        process::exit(self.exit_code);
    }

    /// Present error to user without exiting
    pub fn present_error(&self) {
        eprintln!("{}", self.format_for_user());
    }

    /// Format error message for user presentation
    pub fn format_for_user(&self) -> String {
        let severity_prefix = match self.error.severity() {
            ErrorSeverity::Critical => "🔒 SECURITY ERROR",
            ErrorSeverity::Error => "❌ ERROR",
            ErrorSeverity::Warning => "⚠️  WARNING",
        };

        let user_message = self.error.user_friendly_message();
        
        let footer = if self.error.is_recoverable() {
            "\n💡 This error can typically be resolved by following the suggestions above."
        } else {
            "\n💡 If this error persists, please check the documentation or contact support."
        };

        format!(
            "{} in '{}' command\n\n{}{}\n\nExit code: {}",
            severity_prefix,
            self.command,
            user_message,
            footer,
            self.exit_code
        )
    }

    /// Determine appropriate exit code for an error
    fn determine_exit_code(error: &ApplicationError) -> i32 {
        if error.suggests_wrong_password() {
            return exit_codes::AUTHENTICATION_ERROR;
        }

        if error.is_security_related() {
            return exit_codes::SECURITY_ERROR;
        }

        match error {
            ApplicationError::Domain(domain_err) => {
                use crate::domain::errors::*;
                match domain_err {
                    DomainError::FileSystemError(fs_err) => {
                        match fs_err {
                            FileSystemError::FileNotFound { .. } |
                            FileSystemError::PermissionDenied { .. } => exit_codes::FILE_ERROR,
                            FileSystemError::InsufficientDiskSpace { .. } => exit_codes::RESOURCE_ERROR,
                            _ => exit_codes::GENERAL_ERROR,
                        }
                    }
                    DomainError::InputValidationError(_) => exit_codes::INPUT_ERROR,
                    DomainError::ConfigurationError(_) => exit_codes::CONFIG_ERROR,
                    DomainError::ResourceError(_) => exit_codes::RESOURCE_ERROR,
                    DomainError::SecurityViolation(_) => exit_codes::SECURITY_ERROR,
                    _ => exit_codes::GENERAL_ERROR,
                }
            }
            ApplicationError::Infrastructure(infra_err) => {
                use crate::infrastructure::errors::*;
                match infra_err {
                    InfrastructureError::FileSystem(_) => exit_codes::FILE_ERROR,
                    InfrastructureError::Configuration(_) => exit_codes::CONFIG_ERROR,
                    InfrastructureError::Resource(_) => exit_codes::RESOURCE_ERROR,
                    InfrastructureError::Terminal(term_err) => {
                        match term_err {
                            TerminalError::UserCancelled => exit_codes::USER_CANCELLED,
                            _ => exit_codes::GENERAL_ERROR,
                        }
                    }
                    _ => exit_codes::GENERAL_ERROR,
                }
            }
            ApplicationError::Validation(_) => exit_codes::INPUT_ERROR,
            _ => exit_codes::GENERAL_ERROR,
        }
    }

    /// Format error for debug output (includes technical details)
    pub fn format_for_debug(&self) -> String {
        format!(
            "CLI Error in '{}' command:\n\
            Exit Code: {}\n\
            Severity: {:?}\n\
            Application Error: {:?}\n\
            User Message: {}",
            self.command,
            self.exit_code,
            self.error.severity(),
            self.error,
            self.error.user_friendly_message()
        )
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_for_user())
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<ApplicationError> for CliError {
    fn from(error: ApplicationError) -> Self {
        Self::new(error, "unknown")
    }
}

/// Helper trait for easy CLI error handling
pub trait CliErrorExt<T> {
    /// Convert result to CLI error with command context
    fn cli_context(self, command: &str) -> Result<T, CliError>;
    
    /// Present error and exit if it's an error
    fn unwrap_or_exit(self, command: &str) -> T;
}

impl<T, E> CliErrorExt<T> for Result<T, E> 
where
    E: Into<ApplicationError>,
{
    fn cli_context(self, command: &str) -> Result<T, CliError> {
        self.map_err(|e| CliError::new(e.into(), command))
    }

    fn unwrap_or_exit(self, command: &str) -> T {
        match self.cli_context(command) {
            Ok(value) => value,
            Err(cli_error) => cli_error.present_and_exit(),
        }
    }
}

/// Print success message with consistent formatting
pub fn print_success(command: &str, message: &str) {
    println!("✅ {} - {}", command, message);
}

/// Print warning message with consistent formatting
pub fn print_warning(command: &str, message: &str) {
    eprintln!("⚠️  {} - {}", command, message);
}

/// Print info message with consistent formatting
pub fn print_info(command: &str, message: &str) {
    println!("ℹ️  {} - {}", command, message);
}

/// Confirm a potentially destructive operation
pub fn confirm_destructive_operation(operation: &str) -> Result<bool, ApplicationError> {
    use crate::infrastructure::errors::{TerminalError, InfrastructureError};
    use std::io::{self, Write};

    print!("⚠️  This will {}. Continue? (y/N): ", operation);
    io::stdout().flush().map_err(|e| {
        InfrastructureError::Terminal(TerminalError::FormattingError {
            reason: e.to_string(),
        })
    })?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| {
        InfrastructureError::Terminal(TerminalError::PasswordInputFailed {
            reason: e.to_string(),
        })
    })?;

    Ok(input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::errors::*;
    use crate::application::errors::*;

    #[test]
    fn test_exit_code_determination() {
        // Authentication error
        let auth_error = ApplicationError::Domain(DomainError::AuthenticationFailed {
            context: "test".to_string(),
        });
        assert_eq!(CliError::determine_exit_code(&auth_error), exit_codes::AUTHENTICATION_ERROR);

        // File error
        let file_error = ApplicationError::Domain(DomainError::FileSystemError(
            FileSystemError::FileNotFound { path: "test".to_string() }
        ));
        assert_eq!(CliError::determine_exit_code(&file_error), exit_codes::FILE_ERROR);

        // Security error
        let security_error = ApplicationError::Domain(DomainError::SecurityViolation(
            SecurityViolation::DoubleEncryptionAttempt { file: "test".to_string() }
        ));
        assert_eq!(CliError::determine_exit_code(&security_error), exit_codes::SECURITY_ERROR);
    }

    #[test]
    fn test_cli_error_formatting() {
        let app_error = ApplicationError::Domain(DomainError::AuthenticationFailed {
            context: "wrong password".to_string(),
        });
        let cli_error = CliError::new(app_error, "shadow");
        
        let formatted = cli_error.format_for_user();
        assert!(formatted.contains("🔒 SECURITY ERROR"));
        assert!(formatted.contains("'shadow' command"));
        assert!(formatted.contains("incorrect password"));
        assert!(formatted.contains("Exit code: 2"));
    }

    #[test]
    fn test_severity_formatting() {
        let warning_error = ApplicationError::Workflow(WorkflowError::PartialFailure {
            total: 5,
            failed: 1,
            error_count: 1,
        });
        let cli_error = CliError::new(warning_error, "shadow");
        
        let formatted = cli_error.format_for_user();
        assert!(formatted.contains("⚠️  WARNING"));
    }

    #[test]
    fn test_cli_error_ext() {
        let result: Result<i32, DomainError> = Err(DomainError::AuthenticationFailed {
            context: "test".to_string(),
        });
        
        let cli_result = result.cli_context("test-command");
        assert!(cli_result.is_err());
        
        if let Err(cli_error) = cli_result {
            assert_eq!(cli_error.command(), "test-command");
            assert_eq!(cli_error.exit_code(), exit_codes::AUTHENTICATION_ERROR);
        }
    }

    #[test]
    fn test_formatting_functions() {
        // These are just smoke tests since the functions print to stdout/stderr
        print_success("test", "operation completed");
        print_warning("test", "potential issue");
        print_info("test", "information message");
    }
}