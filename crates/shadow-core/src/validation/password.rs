// shadow-core/src/validation/password.rs
// Professional password validation based purely on entropy
// No arbitrary length requirements - only cryptographic security matters

use crate::errors::ValidationError;
use crate::memory::SecureString;

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

/// Validate password strength using zxcvbn industry-standard algorithm
/// Pure function - no side effects
fn validate_password_entropy(password: &SecureString) -> Result<(), ValidationError> {
    let estimate = zxcvbn::zxcvbn(password.as_str(), &[]);

    // Score 3 = "Safely unguessable: moderate protection from offline slow-hash scenario"
    if estimate.score() < zxcvbn::Score::Three {
        let feedback_msg = format_feedback(&estimate);
        return Err(ValidationError::WeakPassword {
            reason: format!(
                "Password strength insufficient (score {}/4). {}. Estimated crack time: {}",
                estimate.score(),
                feedback_msg,
                estimate.crack_times().offline_slow_hashing_1e4_per_second()
            ),
        });
    }

    Ok(())
}

/// Format zxcvbn feedback into user-friendly message
fn format_feedback(estimate: &zxcvbn::Entropy) -> String {
    if let Some(feedback) = estimate.feedback() {
        let mut suggestions = Vec::new();

        if let Some(warning) = feedback.warning() {
            suggestions.push(warning.to_string());
        }

        suggestions.extend(feedback.suggestions().iter().map(|s| s.to_string()));

        if suggestions.is_empty() {
            "Use a stronger password".to_string()
        } else {
            suggestions.join(". ")
        }
    } else {
        "Use a stronger password".to_string()
    }
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

    #[test]
    fn test_validate_weak_password() {
        let password = SecureString::new("123456".to_string());
        let result = validate_password_entropy(&password);
        assert!(matches!(result, Err(ValidationError::WeakPassword { .. })));
    }

    #[test]
    fn test_validate_strong_password() {
        let password = SecureString::new("correct horse battery staple".to_string());
        let result = validate_password_entropy(&password);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_short_random_password() {
        let password = SecureString::new("Tr0ub4dor&3".to_string());
        let result = validate_password_entropy(&password);
        // This should pass as it's a well-known strong password from XKCD
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_long_passphrase() {
        let password = SecureString::new("The quick brown fox jumps over the lazy dog".to_string());
        let result = validate_password_entropy(&password);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pattern_detection() {
        let password = SecureString::new("password123".to_string());
        let result = validate_password_entropy(&password);
        assert!(matches!(result, Err(ValidationError::WeakPassword { .. })));
    }

    #[test]
    fn test_entropy_calculation() {
        let weak = SecureString::new("password".to_string());
        let strong = SecureString::new("Tr0ub4dor&3".to_string());

        let weak_result = validate_password_entropy(&weak);
        let strong_result = validate_password_entropy(&strong);

        assert!(matches!(weak_result, Err(_)));
        assert!(strong_result.is_ok());
    }
}
