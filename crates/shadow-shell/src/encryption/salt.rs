use rand::rand_core::{OsRng, TryRngCore};

use crate::errors::{WorkflowError, WorkflowResult};

pub fn generate_salt() -> WorkflowResult<[u8; 16]> {
    let mut buffer = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut buffer)
        .map_err(|e| WorkflowError::SaltGeneration(format!("Failed to generate salt: {}", e)))?;

    Ok(buffer)
}
