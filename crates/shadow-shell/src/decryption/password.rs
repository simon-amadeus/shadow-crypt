use rpassword;
use shadow_core::memory::SecureString;

use crate::errors::{WorkflowError, WorkflowResult};

/// Prompt user for password
pub fn prompt_for_password() -> WorkflowResult<SecureString> {
    let password = rpassword::prompt_password("Enter password: ")
        .map_err(|e| WorkflowError::Password(format!("Failed to read password: {}", e)))
        .map(SecureString::new)?;

    Ok(password)
}
