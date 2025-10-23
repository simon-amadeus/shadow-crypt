use rpassword;
use shadow_core::memory::SecureString;
use zeroize::Zeroize;

use crate::errors::{WorkflowError, WorkflowResult};

/// Prompt user for password with confirmation
pub fn prompt_for_password_with_confirmation(allow_weak: bool) -> WorkflowResult<SecureString> {
    let mut password1 = rpassword::prompt_password("Enter password: ")
        .map_err(|e| WorkflowError::UserInput(format!("Failed to read password: {}", e)))?;
    let secure_password1 = SecureString::new(password1.clone());
    password1.zeroize(); // Clear plain password from memory

    let mut password2 = rpassword::prompt_password("Confirm password: ")
        .map_err(|e| WorkflowError::UserInput(format!("Failed to read password: {}", e)))?;
    let secure_password2 = SecureString::new(password2.clone());
    password2.zeroize(); // Clear plain password from memory

    constant_time_eq(
        secure_password1.as_str().as_bytes(),
        secure_password2.as_str().as_bytes(),
    )
    .then_some(())
    .ok_or(WorkflowError::PasswordMismatch)?;

    validate_password_requirements(&secure_password1, allow_weak)
        .map_err(|e| WorkflowError::Password(e.to_string()))?;

    Ok(SecureString::new(password1))
}

pub fn validate_password_format(password: &SecureString) -> Result<(), WorkflowError> {
    if password.is_empty() {
        return Err(WorkflowError::EmptyPassword);
    }

    Ok(())
}

fn validate_password_requirements(
    password: &SecureString,
    allow_weak: bool,
) -> Result<(), WorkflowError> {
    // Basic format check
    validate_password_format(password)?;

    // Professional entropy validation (the only security requirement that matters)
    if !allow_weak {
        validate_password_entropy(password)?;
    }

    Ok(())
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
