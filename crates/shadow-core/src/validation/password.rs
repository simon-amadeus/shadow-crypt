// shadow-core/src/validation/password.rs
// Professional password validation based purely on entropy
// No arbitrary length requirements - only cryptographic security matters

use crate::errors::ValidationError;
use crate::memory::SecureString;

pub use super::entropy::validate_password_entropy;

/// Validate password format (basic structural requirements only)
/// Pure function - no side effects
pub fn validate_password_format(password: &SecureString) -> Result<(), ValidationError> {
    if password.is_empty() {
        return Err(ValidationError::EmptyPassword);
    }

    // No other format requirements - entropy is what matters for security
    Ok(())
}

/// Validate password strength using professional entropy analysis
/// This is the main validation function that should be used
/// Pure function - no side effects
pub fn validate_password_strength(password: &SecureString) -> Result<(), ValidationError> {
    // Basic format check
    validate_password_format(password)?;

    // Professional entropy validation (the only security requirement that matters)
    validate_password_entropy(password)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_password_format_empty() {
        let password = SecureString::new(String::new());
        let result = validate_password_format(&password);
        assert!(matches!(result, Err(ValidationError::EmptyPassword)));
    }

    #[test]
    fn test_validate_password_format_valid() {
        let password = SecureString::new("x".to_string()); // Even 1 char is valid format
        let result = validate_password_format(&password);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_password_strength_delegates_to_entropy() {
        // This test verifies that strength validation uses entropy checking
        let weak_password = SecureString::new("abc".to_string());
        let result = validate_password_strength(&weak_password);
        // Should fail on entropy, not length
        assert!(matches!(result, Err(ValidationError::WeakPassword { .. })));
    }
}
