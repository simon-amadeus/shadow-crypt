use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::{
    errors::KeyDerivationError, memory::SecureKey, report::KeyDerivationReport,
    v2::key::KeyDerivationParams,
};

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
        kdf_params.memory_cost,
        kdf_params.time_cost,
        kdf_params.parallelism,
        kdf_params.key_size,
        duration,
    );

    Ok((key, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{profile::SecurityProfile, v2::key::KeyDerivationParams};

    fn get_test_params() -> KeyDerivationParams {
        KeyDerivationParams::from(SecurityProfile::Test)
    }

    #[test]
    fn test_derive_key_success() {
        let password = b"test_password";
        let salt = b"test_salt_16_bytes";
        let params = get_test_params();

        let (key, report) = derive_key(password, salt, &params).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
        assert_eq!(report.algorithm, "Argon2id");
        assert_eq!(report.algorithm_version, "19");
        assert_eq!(report.memory_cost_kib, params.memory_cost);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"test_password";
        let salt = b"test_salt_16_bytes";
        let params = get_test_params();

        let (key1, _) = derive_key(password, salt, &params).unwrap();
        let (key2, _) = derive_key(password, salt, &params).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let salt = b"test_salt_16_bytes";
        let params = get_test_params();

        let (key1, _) = derive_key(b"password1", salt, &params).unwrap();
        let (key2, _) = derive_key(b"password2", salt, &params).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_derive_key_invalid_parameters() {
        let invalid_params = KeyDerivationParams::new(0, 1, 1, 32);
        let result = derive_key(b"pw", b"test_salt_16_bytes", &invalid_params);
        assert!(matches!(
            result,
            Err(KeyDerivationError::InvalidParameters(_))
        ));
    }
}
