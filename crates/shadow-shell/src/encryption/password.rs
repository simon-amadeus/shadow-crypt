use rpassword;
use shadow_core::{memory::SecureString, profile::SecurityProfile};

use crate::errors::{WorkflowError, WorkflowResult};

/// Prompt user for password with confirmation
pub fn prompt_for_password_with_confirmation(
    security_profile: &SecurityProfile,
) -> WorkflowResult<SecureString> {
    let password1 = rpassword::prompt_password("Enter password: ")
        .map_err(|e| WorkflowError::Password(format!("Failed to read password: {}", e)))
        .map(SecureString::new)?;

    let password2 = rpassword::prompt_password("Confirm password: ")
        .map_err(|e| WorkflowError::Password(format!("Failed to read password: {}", e)))
        .map(SecureString::new)?;

    constant_time_eq(password1.as_str().as_bytes(), password2.as_str().as_bytes())
        .then_some(())
        .ok_or(WorkflowError::Password(
            "Passwords do not match".to_string(),
        ))?;

    validate_password_requirements(&password1, security_profile)
        .map_err(|e| WorkflowError::Password(e.to_string()))?;

    Ok(password1)
}

pub fn validate_password_format(password: &SecureString) -> Result<(), WorkflowError> {
    if password.is_empty() {
        return Err(WorkflowError::Password(
            "Password cannot be empty".to_string(),
        ));
    }

    Ok(())
}

fn validate_password_requirements(
    password: &SecureString,
    security_profile: &SecurityProfile,
) -> Result<(), WorkflowError> {
    // Basic format check
    validate_password_format(password)?;

    // Professional entropy validation (the only security requirement that matters)
    match security_profile {
        SecurityProfile::Test => Ok(()), // Skip entropy check in test mode
        SecurityProfile::Production => validate_password_entropy(password),
    }
}

/// Validate password strength using zxcvbn industry-standard algorithm
/// Pure function - no side effects
fn validate_password_entropy(password: &SecureString) -> Result<(), WorkflowError> {
    let estimate = zxcvbn::zxcvbn(password.as_str(), &[]);

    // Score 3 = "Safely unguessable: moderate protection from offline slow-hash scenario"
    if estimate.score() < zxcvbn::Score::Three {
        let feedback_msg = format_feedback(&estimate);
        return Err(WorkflowError::Password(format!(
            "Password strength insufficient (score {}/4). {}. Estimated crack time: {}",
            estimate.score(),
            feedback_msg,
            estimate.crack_times().offline_slow_hashing_1e4_per_second()
        )));
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

use subtle::ConstantTimeEq;

/// Constant-time equality comparison for security-sensitive data
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadow_core::profile::SecurityProfile;

    #[test]
    fn test_validate_password_format_empty() {
        let empty = SecureString::new(String::new());
        assert!(validate_password_format(&empty).is_err());
    }

    #[test]
    fn test_validate_password_format_non_empty() {
        let password = SecureString::new("test".to_string());
        assert!(validate_password_format(&password).is_ok());
    }

    #[test]
    fn test_validate_password_requirements_test_profile() {
        let password = SecureString::new("weak".to_string());
        assert!(validate_password_requirements(&password, &SecurityProfile::Test).is_ok());
    }

    #[test]
    fn test_validate_password_requirements_production_weak() {
        let password = SecureString::new("password".to_string());
        assert!(validate_password_requirements(&password, &SecurityProfile::Production).is_err());
    }

    #[test]
    fn test_validate_password_requirements_production_strong() {
        let password = SecureString::new("Tr0ub4dour&3!".to_string());
        assert!(validate_password_requirements(&password, &SecurityProfile::Production).is_ok());
    }

    #[test]
    fn test_validate_password_entropy_weak() {
        let password = SecureString::new("123456".to_string());
        assert!(validate_password_entropy(&password).is_err());
    }

    #[test]
    fn test_validate_password_entropy_strong() {
        let password = SecureString::new("CorrectHorseBatteryStaple".to_string());
        assert!(validate_password_entropy(&password).is_ok());
    }

    #[test]
    fn test_format_feedback_no_feedback() {
        // Use a very strong password that likely has no feedback
        let estimate = zxcvbn::zxcvbn("Tr0ub4dour&3!BatteryStaple", &[]);
        let feedback = format_feedback(&estimate);
        // If it has feedback, it should be formatted; if not, default message
        // This test ensures the function doesn't panic and returns a string
        assert!(!feedback.is_empty());
    }

    #[test]
    fn test_constant_time_eq_equal() {
        let a = b"test";
        let b = b"test";
        assert!(constant_time_eq(a, b));
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        let a = b"test";
        let b = b"different";
        assert!(!constant_time_eq(a, b));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        let a = b"test";
        let b = b"testing";
        assert!(!constant_time_eq(a, b));
    }
}
