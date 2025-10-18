// shadow-shell/src/cli_helpers.rs
// CLI parsing and user interaction utilities

use rpassword;
use shadow_core::memory::SecureString;
use std::io::{self, Write};

use crate::errors::{EncryptionError, EncryptionResult};

/// Prompt user for password with confirmation
/// Side effect: User interaction via stdin/stdout
pub fn prompt_for_password_with_confirmation(allow_weak: bool) -> EncryptionResult<SecureString> {
    print!("Enter password: ");
    io::stdout()
        .flush()
        .map_err(|e| EncryptionError::UserInput(format!("Failed to flush stdout: {}", e)))?;

    let password1 = rpassword::read_password()
        .map_err(|e| EncryptionError::UserInput(format!("Failed to read password: {}", e)))?;

    print!("Confirm password: ");
    io::stdout()
        .flush()
        .map_err(|e| EncryptionError::UserInput(format!("Failed to flush stdout: {}", e)))?;

    let password2 = rpassword::read_password()
        .map_err(|e| EncryptionError::UserInput(format!("Failed to read password: {}", e)))?;

    if password1 != password2 {
        return Err(EncryptionError::PasswordsDoNotMatch);
    }

    if password1.is_empty() {
        return Err(EncryptionError::EmptyPassword);
    }

    // Convert to SecureString for validation
    let secure_password = SecureString::new(password1.clone());

    // Validate password strength only if not allowing weak passwords
    if !allow_weak {
        validate_password_strength(&secure_password)
            .map_err(|e| EncryptionError::Password(e.to_string()))?;
    }

    Ok(SecureString::new(password1))
}

/// Validate password format (basic structural requirements only)
/// Pure function - no side effects
pub fn validate_password_format(password: &SecureString) -> Result<(), EncryptionError> {
    if password.is_empty() {
        return Err(EncryptionError::EmptyPassword);
    }

    // No other format requirements - entropy is what matters for security
    Ok(())
}

/// Validate password strength using professional entropy analysis
/// This is the main validation function that should be used
/// Pure function - no side effects
pub fn validate_password_strength(password: &SecureString) -> Result<(), EncryptionError> {
    // Basic format check
    validate_password_format(password)?;

    // Professional entropy validation (the only security requirement that matters)
    validate_password_entropy(password)?;

    Ok(())
}

/// Validate password strength using zxcvbn industry-standard algorithm
/// Pure function - no side effects
fn validate_password_entropy(password: &SecureString) -> Result<(), EncryptionError> {
    let estimate = zxcvbn::zxcvbn(password.as_str(), &[]);

    // Score 3 = "Safely unguessable: moderate protection from offline slow-hash scenario"
    if estimate.score() < zxcvbn::Score::Three {
        let feedback_msg = format_feedback(&estimate);
        return Err(EncryptionError::Password(format!(
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
