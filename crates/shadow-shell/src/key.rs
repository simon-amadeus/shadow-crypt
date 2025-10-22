use crate::errors::{WorkflowError, WorkflowResult};
use argon2::{Algorithm, Argon2, Params, Version};
use shadow_core::v1::key::KeyDerivationParams;

pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    params: &KeyDerivationParams,
) -> WorkflowResult<[u8; 32]> {
    let algorithm = Algorithm::Argon2id;
    let version = Version::V0x13; // Version 19
    let params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(params.key_size as usize),
    )
    .map_err(|e| {
        WorkflowError::KeyDerivation(format!("Invalid key derivation parameters: {}", e))
    })?;
    let context = Argon2::new(algorithm, version, params);

    let mut key = [0u8; 32];
    context
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| WorkflowError::KeyDerivation(format!("Key derivation failed: {}", e)))?;

    Ok(key)
}
