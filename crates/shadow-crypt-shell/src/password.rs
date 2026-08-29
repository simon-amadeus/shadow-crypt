use std::path::Path;

use rpassword;
use shadow_crypt_core::{memory::SecureString, profile::SecurityProfile};

use crate::errors::{WorkflowError, WorkflowResult};

/// Prompt user for password
pub fn prompt_for_password() -> WorkflowResult<SecureString> {
    let password = rpassword::prompt_password("Enter password: ")
        .map_err(|e| WorkflowError::Password(format!("Failed to read password: {}", e)))
        .map(SecureString::new)?;

    Ok(password)
}

/// Reads a password from a file for non-interactive use. A single trailing
/// newline (as left by most editors and `echo`) is stripped; everything else
/// is taken verbatim.
pub fn read_password_from_file(path: &Path) -> WorkflowResult<SecureString> {
    let mut content = std::fs::read_to_string(path).map_err(|e| {
        WorkflowError::Password(format!(
            "Failed to read password file '{}': {}",
            path.display(),
            e
        ))
    })?;
    if content.ends_with('\n') {
        content.pop();
        if content.ends_with('\r') {
            content.pop();
        }
    }

    let password = SecureString::new(content);
    validate_password_format(&password)?;
    Ok(password)
}

/// Password for decryption or listing: read from `password_file` when given,
/// otherwise prompt interactively.
pub fn resolve_password(password_file: Option<&Path>) -> WorkflowResult<SecureString> {
    match password_file {
        Some(path) => read_password_from_file(path),
        None => prompt_for_password(),
    }
}

/// Password for encryption: read from `password_file` when given (strength
/// requirements still apply, but no confirmation is needed since there is no
/// typo risk), otherwise prompt interactively with confirmation.
pub fn resolve_encryption_password(
    password_file: Option<&Path>,
    security_profile: &SecurityProfile,
) -> WorkflowResult<SecureString> {
    match password_file {
        Some(path) => {
            let password = read_password_from_file(path)?;
            validate_password_requirements(&password, security_profile)?;
            Ok(password)
        }
        None => prompt_for_password_with_confirmation(security_profile),
    }
}

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

/// Compares two byte slices for equality in constant time when lengths are equal.
/// A length mismatch is detected immediately (not in constant time), which is
/// acceptable for interactive password confirmation but not for HMAC verification.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadow_crypt_core::profile::SecurityProfile;

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

    #[test]
    fn test_read_password_from_file() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, b"secret-password\n").unwrap();

        let password = read_password_from_file(file.path()).unwrap();
        assert_eq!(password.as_str(), "secret-password");
    }

    #[test]
    fn test_read_password_from_file_strips_crlf() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, b"secret-password\r\n").unwrap();

        let password = read_password_from_file(file.path()).unwrap();
        assert_eq!(password.as_str(), "secret-password");
    }

    #[test]
    fn test_read_password_from_file_keeps_inner_content_verbatim() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, b"  spaced password ").unwrap();

        let password = read_password_from_file(file.path()).unwrap();
        assert_eq!(password.as_str(), "  spaced password ");
    }

    #[test]
    fn test_read_password_from_empty_file_rejected() {
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(read_password_from_file(file.path()).is_err());
    }

    #[test]
    fn test_read_password_from_missing_file_rejected() {
        let result = read_password_from_file(std::path::Path::new("/nonexistent/password"));
        assert!(result.is_err());
    }
}
