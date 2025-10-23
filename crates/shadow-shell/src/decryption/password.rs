use rpassword;
use shadow_core::memory::SecureString;
use zeroize::Zeroize;

use crate::errors::{WorkflowError, WorkflowResult};

/// Prompt user for password
pub fn prompt_for_password() -> WorkflowResult<SecureString> {
    let mut password = rpassword::prompt_password("Enter password: ")
        .map_err(|e| WorkflowError::Password(format!("Failed to read password: {}", e)))?;
    let secure_password = SecureString::new(password.clone());
    password.zeroize(); // Clear plain password from memory

    Ok(secure_password)
}
