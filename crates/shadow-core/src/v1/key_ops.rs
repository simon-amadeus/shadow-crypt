use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::{memory::SecureKey, report::KeyDerivationReport, v1::key::KeyDerivationParams};

pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    kdf_params: &KeyDerivationParams,
) -> Result<(SecureKey, KeyDerivationReport), KeyDerivationError> {
    let start_time = std::time::Instant::now();
    let algorithm = Algorithm::Argon2id;
    let version = Version::V0x13; // Version 19
    let params = Params::new(
        kdf_params.memory_cost,
        kdf_params.time_cost,
        kdf_params.parallelism,
        Some(kdf_params.key_size as usize),
    )
    .map_err(|e| KeyDerivationError::InvalidParameters(format!("Invalid KDF parameters: {}", e)))?;
    let context = Argon2::new(algorithm, version, params);

    let mut buffer = [0u8; 32];
    context
        .hash_password_into(password, salt, &mut buffer)
        .map_err(|e| {
            KeyDerivationError::DerivationFailed(format!("Key derivation failed: {}", e))
        })?;

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

#[derive(Debug)]
pub enum KeyDerivationError {
    InvalidParameters(String),
    DerivationFailed(String),
}

impl std::fmt::Display for KeyDerivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyDerivationError::InvalidParameters(msg) => write!(f, "Invalid parameters: {}", msg),
            KeyDerivationError::DerivationFailed(msg) => write!(f, "Derivation failed: {}", msg),
        }
    }
}

impl std::error::Error for KeyDerivationError {}
