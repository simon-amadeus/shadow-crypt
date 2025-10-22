use rand::rand_core::{OsRng, TryRngCore};

use crate::errors::{WorkflowError, WorkflowResult};

pub fn generate_nonce() -> WorkflowResult<[u8; 24]> {
    let mut buffer = [0u8; 24];
    OsRng
        .try_fill_bytes(&mut buffer)
        .map_err(|e| WorkflowError::NonceGeneration(format!("Failed to generate nonce: {}", e)))?;

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

    #[test]
    fn test_generate_nonce_uniqueness() {
        let nonce1 = generate_nonce().expect("Failed to generate nonce");
        let nonce2 = generate_nonce().expect("Failed to generate nonce");
        assert_ne!(nonce1, nonce2, "Generated nonces should be unique");
    }
}
