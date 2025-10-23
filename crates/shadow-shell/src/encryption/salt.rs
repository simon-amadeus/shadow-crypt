use rand::rand_core::{OsRng, TryRngCore};

use crate::errors::{WorkflowError, WorkflowResult};

pub fn generate_salt() -> WorkflowResult<[u8; 16]> {
    let mut buffer = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut buffer)
        .map_err(|e| WorkflowError::SaltGeneration(format!("Failed to generate salt: {}", e)))?;

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::generate_salt;

    #[test]
    fn test_generate_salt_length() {
        let salt = generate_salt().expect("Failed to generate salt");
        assert_eq!(salt.len(), 16);
    }

    #[test]
    fn test_generate_salt_uniqueness() {
        let mut salts = std::collections::HashSet::new();
        for _ in 0..100 {
            let salt = generate_salt().expect("Failed to generate salt");
            assert!(salts.insert(salt), "Generated salt was not unique");
        }
    }
}
