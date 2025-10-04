//! # Terminal Infrastructure
//!
//! Terminal/CLI operations and password repository implementations.

use crate::domain::repositories::password_repository::{
    PasswordRepository, PasswordInputError, PasswordStrength, CryptoResult
};
use std::io::{self, Write};

/// Terminal-based password repository implementation
pub struct TerminalPasswordRepository;

impl TerminalPasswordRepository {
    /// Create a new terminal password repository
    pub fn new() -> Self {
        Self
    }
}

impl Default for TerminalPasswordRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordRepository for TerminalPasswordRepository {
    fn prompt_password(&self, prompt: &str) -> Result<String, PasswordInputError> {
        // Print prompt
        print!("{}", prompt);
        io::stdout().flush()
            .map_err(|e| PasswordInputError::IoError(e.to_string()))?;

        // Read password securely (hidden input)
        rpassword::read_password()
            .map_err(|e| PasswordInputError::TerminalError(e.to_string()))
    }

    fn prompt_password_with_confirmation(&self, prompt: &str) -> CryptoResult<String> {
        // This is a legacy method - we'll implement our own double verification
        // in the password service instead
        let password = self.prompt_password(prompt)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        Ok(password)
    }

    fn validate_password_strength(&self, password: &str) -> PasswordStrength {
        // Basic password strength validation
        let mut issues = Vec::new();
        
        if password.len() < 8 {
            issues.push("Password should be at least 8 characters long".to_string());
        }
        
        if !password.chars().any(|c| c.is_ascii_digit()) {
            issues.push("Password should contain at least one number".to_string());
        }
        
        if !password.chars().any(|c| c.is_ascii_uppercase()) {
            issues.push("Password should contain at least one uppercase letter".to_string());
        }
        
        if !password.chars().any(|c| c.is_ascii_lowercase()) {
            issues.push("Password should contain at least one lowercase letter".to_string());
        }
        
        if issues.is_empty() {
            if password.len() >= 12 {
                PasswordStrength::Strong
            } else {
                PasswordStrength::Moderate
            }
        } else {
            PasswordStrength::Weak { issues }
        }
    }
}