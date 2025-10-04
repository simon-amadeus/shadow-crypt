//! # PasswordRepository Interface
//!
//! Handles password input and validation (no persistence in stateless design).
//! Based on specs/DOMAIN_ARCHITECTURE.md

/// Result type for crypto operations
pub type CryptoResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Password strength assessment
#[derive(Debug, Clone)]
pub enum PasswordStrength {
    Weak { issues: Vec<String> },
    Moderate,
    Strong,
}

/// Handles password input and validation (no persistence)
pub trait PasswordRepository: Send + Sync {
    /// Prompt for password input
    fn prompt_password(&self, prompt: &str) -> CryptoResult<String>;
    
    /// Prompt for password with confirmation
    fn prompt_password_with_confirmation(&self, prompt: &str) -> CryptoResult<String>;
    
    /// Validate password strength
    fn validate_password_strength(&self, password: &str) -> PasswordStrength;
}