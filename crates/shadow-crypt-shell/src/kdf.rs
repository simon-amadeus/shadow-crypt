//! Guards for Argon2 parameters read from untrusted file headers.
//!
//! Every code path that derives a key from header-supplied parameters
//! (decryption and listing alike) must validate them here first, so a
//! crafted .shadow file cannot request an enormous allocation or an
//! excessive amount of CPU time.

use crate::errors::{WorkflowError, WorkflowResult};

/// Upper bounds for KDF parameters read from untrusted file headers.
/// These prevent a crafted file from causing OOM or excessive CPU use.
pub const MAX_KDF_MEMORY_KIB: u32 = 8 * 1024 * 1024; // 8 GiB
pub const MAX_KDF_ITERATIONS: u32 = 1_000;
pub const MAX_KDF_PARALLELISM: u32 = 256;
pub const MAX_KDF_KEY_SIZE: u8 = 64;

/// Validates KDF parameters taken from an untrusted file header.
///
/// Takes raw values rather than a version-specific params struct so that
/// every format version can use the same bounds.
pub fn validate_untrusted_kdf_params(
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    key_size: u8,
) -> WorkflowResult<()> {
    if memory_cost > MAX_KDF_MEMORY_KIB {
        return Err(WorkflowError::UserInput(format!(
            "KDF memory cost in file header is too large: {} KiB (max {} KiB)",
            memory_cost, MAX_KDF_MEMORY_KIB
        )));
    }
    if time_cost > MAX_KDF_ITERATIONS {
        return Err(WorkflowError::UserInput(format!(
            "KDF iteration count in file header is too large: {} (max {})",
            time_cost, MAX_KDF_ITERATIONS
        )));
    }
    if parallelism > MAX_KDF_PARALLELISM {
        return Err(WorkflowError::UserInput(format!(
            "KDF parallelism in file header is too large: {} (max {})",
            parallelism, MAX_KDF_PARALLELISM
        )));
    }
    if key_size > MAX_KDF_KEY_SIZE {
        return Err(WorkflowError::UserInput(format!(
            "KDF key size in file header is too large: {} bytes (max {})",
            key_size, MAX_KDF_KEY_SIZE
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_kdf_params_accepted() {
        assert!(validate_untrusted_kdf_params(1024, 1, 1, 32).is_ok());
    }

    #[test]
    fn test_memory_cost_too_large() {
        assert!(validate_untrusted_kdf_params(MAX_KDF_MEMORY_KIB + 1, 1, 1, 32).is_err());
    }

    #[test]
    fn test_memory_cost_at_limit_accepted() {
        assert!(validate_untrusted_kdf_params(MAX_KDF_MEMORY_KIB, 1, 1, 32).is_ok());
    }

    #[test]
    fn test_iterations_too_large() {
        assert!(validate_untrusted_kdf_params(1024, MAX_KDF_ITERATIONS + 1, 1, 32).is_err());
    }

    #[test]
    fn test_parallelism_too_large() {
        assert!(validate_untrusted_kdf_params(1024, 1, MAX_KDF_PARALLELISM + 1, 32).is_err());
    }

    #[test]
    fn test_key_size_too_large() {
        assert!(validate_untrusted_kdf_params(1024, 1, 1, MAX_KDF_KEY_SIZE + 1).is_err());
    }

    #[test]
    fn test_production_params_accepted() {
        let params = shadow_crypt_core::v1::key::KeyDerivationParams::production_defaults();
        assert!(
            validate_untrusted_kdf_params(
                params.memory_cost,
                params.time_cost,
                params.parallelism,
                params.key_size
            )
            .is_ok()
        );
    }
}
