//! # PasswordRepository Interface
//!
//! Handles password input and validation (no persistence in stateless design).
//! Based on specs/DOMAIN_ARCHITECTURE.md

use std::error::Error;
use std::fmt;

/// Result type for crypto operations
pub type CryptoResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Errors that can occur during password input
#[derive(Debug, Clone, PartialEq)]
pub enum PasswordInputError {
    /// I/O error during password reading
    IoError(String),
    /// Terminal interaction error
    TerminalError(String),
}

impl fmt::Display for PasswordInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PasswordInputError::IoError(msg) => write!(f, "I/O error: {}", msg),
            PasswordInputError::TerminalError(msg) => write!(f, "Terminal error: {}", msg),
        }
    }
}

impl Error for PasswordInputError {}

/// Password strength assessment
#[derive(Debug, Clone)]
pub enum PasswordStrength {
    Weak { issues: Vec<String> },
    Moderate,
    Strong,
}

/// Handles password input and validation (no persistence)
pub trait PasswordRepository: Send + Sync {
    /// Prompt for password input with secure hidden input
    fn prompt_password(&self, prompt: &str) -> Result<String, PasswordInputError>;
    
    /// Prompt for password with confirmation
    fn prompt_password_with_confirmation(&self, prompt: &str) -> CryptoResult<String>;
    
    /// Validate password strength
    fn validate_password_strength(&self, password: &str) -> PasswordStrength;
}