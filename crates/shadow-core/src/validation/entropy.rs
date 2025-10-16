// shadow-core/src/validation/entropy.rs
// Password strength validation using zxcvbn
// Industry-standard password strength estimation

use crate::types::SecureString;
use crate::errors::ValidationError;

/// Validate password strength using zxcvbn industry-standard algorithm
/// Pure function - no side effects
pub fn validate_password_entropy(password: &SecureString) -> Result<(), ValidationError> {
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
        
        suggestions.extend(
            feedback.suggestions()
                .iter()
                .map(|s| s.to_string())
        );
        
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