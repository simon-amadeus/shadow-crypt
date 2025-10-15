//! # Terminal Infrastructure
//!
//! Terminal/CLI operations and password repository implementations.

use crate::domain::repositories::password_repository::{
    PasswordRepository, PasswordInputError, PasswordStrength, CryptoResult
};
use std::io::{self, Write};

/// Terminal-based password repository implementation
pub struct StandardPasswordRepository;

impl StandardPasswordRepository {
    /// Create a new standard password repository
    pub fn new() -> Self {
        Self
    }
}

impl Default for StandardPasswordRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordRepository for StandardPasswordRepository {
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
        loop {
            // Get initial password
            let password1 = self.prompt_password(prompt)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            
            // Check password strength and warn user if weak
            let strength = self.validate_password_strength(&password1);
            if let PasswordStrength::Weak { ref issues } = strength {
                eprintln!("⚠️  Warning: Weak password detected:");
                for issue in issues {
                    eprintln!("   • {}", issue);
                }
                print!("Continue with this password? (y/N): ");
                io::stdout().flush()
                    .map_err(|e| PasswordInputError::IoError(e.to_string()))?;
                
                let mut input = String::new();
                io::stdin().read_line(&mut input)
                    .map_err(|e| PasswordInputError::IoError(e.to_string()))?;
                
                if !input.trim().to_lowercase().starts_with('y') {
                    println!("Please choose a stronger password.");
                    continue;
                }
            }
            
            // Get confirmation
            let confirm_prompt = format!("Confirm {}", prompt.to_lowercase().trim_end_matches(':'));
            let password2 = self.prompt_password(&format!("{}: ", confirm_prompt))
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            
            if password1 == password2 {
                return Ok(password1);
            } else {
                eprintln!("❌ Passwords do not match. Please try again.");
            }
        }
    }

    fn validate_password_strength(&self, password: &str) -> PasswordStrength {
        validate_password_strength_internal(password)
    }
}

/// Internal password strength validation logic (shared with mock)
pub fn validate_password_strength_internal(password: &str) -> PasswordStrength {
    let mut issues = Vec::new();
    
    // Check length
    if password.len() < 8 {
        issues.push("Too short (minimum 8 characters)".to_string());
    }
    
    // Check character variety
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    
    let char_types = [has_lower, has_upper, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();
    
    if char_types < 3 {
        issues.push("Needs more character variety (uppercase, lowercase, digits, symbols)".to_string());
    }
    
    // Check for common patterns
    if password.to_lowercase().contains("password") {
        issues.push("Contains common word 'password'".to_string());
    }
    
    if password.chars().collect::<Vec<_>>().windows(3).any(|w| {
        w[0] as u8 + 1 == w[1] as u8 && w[1] as u8 + 1 == w[2] as u8
    }) {
        issues.push("Contains sequential characters".to_string());
    }
    
    // Determine strength
    if !issues.is_empty() {
        PasswordStrength::Weak { issues }
    } else if password.len() >= 12 && char_types >= 3 {
        PasswordStrength::Strong
    } else {
        PasswordStrength::Moderate
    }
}

// Re-export for backward compatibility
pub use StandardPasswordRepository as TerminalPasswordRepository;