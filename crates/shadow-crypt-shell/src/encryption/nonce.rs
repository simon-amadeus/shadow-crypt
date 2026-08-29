use rand::{rand_core::TryRng, rngs::SysRng};

use crate::errors::{WorkflowError, WorkflowResult};

pub fn generate_nonce() -> WorkflowResult<[u8; 24]> {
    let mut buffer = [0u8; 24];
    SysRng
        .try_fill_bytes(&mut buffer)
        .map_err(|e| WorkflowError::NonceGeneration(format!("Failed to generate nonce: {}", e)))?;

    Ok(buffer)
}

/// Random prefix for the v3 content stream nonces (the per-chunk counter and
/// final flag fill the remaining nonce bytes).
pub fn generate_nonce_prefix() -> WorkflowResult<[u8; 16]> {
    let mut buffer = [0u8; 16];
    SysRng.try_fill_bytes(&mut buffer).map_err(|e| {
        WorkflowError::NonceGeneration(format!("Failed to generate nonce prefix: {}", e))
    })?;

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::generate_nonce;

    #[test]
    fn test_generate_nonce_length() {
        let nonce = generate_nonce().expect("Failed to generate nonce");
        assert_eq!(nonce.len(), 24);
    }
}
