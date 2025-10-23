use crate::errors::{WorkflowError, WorkflowResult};
use argon2::{Algorithm, Argon2, Params, Version};
use shadow_core::{memory::SecureKey, v1::key::KeyDerivationParams};
use zeroize::Zeroize;

pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    kdf_params: &KeyDerivationParams,
) -> WorkflowResult<(SecureKey, KeyDerivationReport)> {
    let start_time = std::time::Instant::now();
    let algorithm = Algorithm::Argon2id;
    let version = Version::V0x13; // Version 19
    let params = Params::new(
        kdf_params.memory_cost,
        kdf_params.time_cost,
        kdf_params.parallelism,
        Some(kdf_params.key_size as usize),
    )
    .map_err(|e| {
        WorkflowError::KeyDerivation(format!("Invalid key derivation parameters: {}", e))
    })?;
    let context = Argon2::new(algorithm, version, params);

    let mut buffer = [0u8; 32];
    context
        .hash_password_into(password, salt, &mut buffer)
        .map_err(|e| WorkflowError::KeyDerivation(format!("Key derivation failed: {}", e)))?;

    let key = SecureKey::new(buffer);
    buffer.zeroize(); // Clear sensitive data from memory

    let duration = start_time.elapsed();
    let report = KeyDerivationReport::new(
        "Argon2id".to_string(),
        format!("{}", version as u8),
        kdf_params,
        duration,
    );

    Ok((key, report))
}

pub struct KeyDerivationReport {
    pub algorithm: String,
    pub algorithm_version: String,
    pub memory_cost_kib: u32,
    pub time_cost_iterations: u32,
    pub parallelism: u32,
    pub key_size_bytes: u8,
    pub duration: std::time::Duration,
}
impl KeyDerivationReport {
    fn new(
        algorithm: String,
        algorithm_version: String,
        params: &KeyDerivationParams,
        duration: std::time::Duration,
    ) -> Self {
        Self {
            algorithm,
            algorithm_version,
            memory_cost_kib: params.memory_cost,
            time_cost_iterations: params.time_cost,
            parallelism: params.parallelism,
            key_size_bytes: params.key_size,
            duration,
        }
    }
}
