// shadow-core/src/validation/password.rs
// Password validation functions
// All code related to validating passwords lives here

use crate::types::SecureString;
use crate::errors::ValidationError;
use crate::constants::{MIN_PASSWORD_LENGTH, MIN_PASSWORD_ENTROPY_BITS};

/// Validate password format and basic requirements
/// Pure function - no side effects
pub fn validate_password_format(password: &SecureString) -> Result<(), ValidationError> {
    if password.is_empty() {
        return Err(ValidationError::EmptyPassword);
    }
    
    if password.as_str().len() < MIN_PASSWORD_LENGTH {
        return Err(ValidationError::WeakPassword {
            reason: format!("Password must be at least {} characters", MIN_PASSWORD_LENGTH),
        });
    }
    
    Ok(())
}

/// Validate password strength using entropy estimation
/// Pure function - deterministic analysis
pub fn validate_password_strength(password: &SecureString) -> Result<(), ValidationError> {
    // First check basic format requirements
    validate_password_format(password)?;
    
    let password_str = password.as_str();
    let entropy = estimate_password_entropy(password_str);
    
    if entropy < MIN_PASSWORD_ENTROPY_BITS {
        return Err(ValidationError::WeakPassword {
            reason: format!(
                "Password entropy {:.1} bits is below minimum {:.1} bits", 
                entropy, 
                MIN_PASSWORD_ENTROPY_BITS
            ),
        });
    }
    
    Ok(())
}

/// Estimate password entropy in bits
/// Pure function - consistent entropy calculation
fn estimate_password_entropy(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }
    
    let mut character_set_size = 0;
    let mut has_lowercase = false;
    let mut has_uppercase = false;
    let mut has_digits = false;
    let mut has_symbols = false;
    
    for ch in password.chars() {
        if ch.is_ascii_lowercase() && !has_lowercase {
            has_lowercase = true;
            character_set_size += 26;
        } else if ch.is_ascii_uppercase() && !has_uppercase {
            has_uppercase = true;
            character_set_size += 26;
        } else if ch.is_ascii_digit() && !has_digits {
            has_digits = true;
            character_set_size += 10;
        } else if !ch.is_alphanumeric() && !has_symbols {
            has_symbols = true;
            character_set_size += 32; // Common symbol characters
        }
    }
    
    if character_set_size == 0 {
        return 0.0;
    }
    
    let length = password.chars().count() as f64;
    length * (character_set_size as f64).log2()
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
    fn test_validate_password_format_too_short() {
        let password = SecureString::new("short".to_string());
        let result = validate_password_format(&password);
        assert!(matches!(result, Err(ValidationError::WeakPassword { .. })));
    }

    #[test]
    fn test_validate_password_format_valid() {
        let password = SecureString::new("valid_password123".to_string());
        let result = validate_password_format(&password);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_password_strength_weak() {
        let password = SecureString::new("abc123".to_string()); // Short password - 6 chars
        let result = validate_password_strength(&password);
        assert!(matches!(result, Err(ValidationError::WeakPassword { .. })));
    }

    #[test]
    fn test_validate_password_strength_strong() {
        let password = SecureString::new("StrongP@ssw0rd123!".to_string());
        let result = validate_password_strength(&password);
        assert!(result.is_ok());
    }

    #[test]
    fn test_estimate_password_entropy_empty() {
        let entropy = estimate_password_entropy("");
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_estimate_password_entropy_lowercase_only() {
        let entropy = estimate_password_entropy("abcdefgh");
        let expected = 8.0 * 26.0_f64.log2(); // 8 chars, 26 possible each
        assert!((entropy - expected).abs() < 0.1);
    }

    #[test]
    fn test_estimate_password_entropy_mixed() {
        let entropy = estimate_password_entropy("Abc123!");
        // Should have uppercase (26) + lowercase (26) + digits (10) + symbols (32) = 94
        let expected = 7.0 * 94.0_f64.log2(); // 7 characters, not 6
        assert!((entropy - expected).abs() < 0.1);
    }
}