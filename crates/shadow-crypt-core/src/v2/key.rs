use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::{
    errors::KeyDerivationError, memory::SecureKey, profile::SecurityProfile,
    report::KeyDerivationReport,
};

/// Argon2id parameters for XChacha20-Poly1305 key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDerivationParams {
    pub memory_cost: u32, // Memory cost in kibibytes (KiB)
    pub time_cost: u32,   // Number of iterations
    pub parallelism: u32, // Number of parallel threads
    pub key_size: u8,     // Output key size in bytes
}

impl KeyDerivationParams {
    pub fn new(memory_cost: u32, time_cost: u32, parallelism: u32, key_size: u8) -> Self {
        Self {
            memory_cost,
            time_cost,
            parallelism,
            key_size,
        }
    }

    /// Production defaults for Argon2id parameters.
    ///
    /// - Memory Cost: 1,048,576 KiB (1 GiB)
    /// - Time Cost: 10 iterations
    /// - Parallelism: 4 threads
    /// - Key Size: 32 bytes (256 bits)
    pub fn production_defaults() -> Self {
        Self {
            memory_cost: 1024 * 1024, // 1,048,576 KiB (1 GiB)
            time_cost: 10,            // 10 iterations
            parallelism: 4,           // 4 threads
            key_size: 32,             // 32 bytes (256 bits)
        }
    }

    /// Test defaults for Argon2id parameters.
    ///
    /// - Memory Cost: 1,024 KiB (1 MiB)
    /// - Time Cost: 1 iteration
    /// - Parallelism: 1 thread
    /// - Key Size: 32 bytes (256 bits)
    pub fn test_defaults() -> Self {
        Self {
            memory_cost: 1024, // 1,024 KiB (1 MiB)
            time_cost: 1,      // 1 iteration
            parallelism: 1,    // 1 thread
            key_size: 32,      // 32 bytes (256 bits)
        }
    }

    /// Derives an encryption key from a password and salt with Argon2id,
    /// using these parameters.
    pub fn derive_key(
        &self,
        password: &[u8],
        salt: &[u8],
    ) -> Result<(SecureKey, KeyDerivationReport), KeyDerivationError> {
        let start_time = std::time::Instant::now();
        let algorithm = Algorithm::Argon2id;
        let version = Version::V0x13; // Version 19
        let params = Params::new(
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            Some(self.key_size as usize),
        )
        .map_err(|e| {
            KeyDerivationError::InvalidParameters(format!("Invalid KDF parameters: {}", e))
        })?;
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
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            self.key_size,
            duration,
        );

        Ok((key, report))
    }
}

impl From<SecurityProfile> for KeyDerivationParams {
    fn from(profile: SecurityProfile) -> Self {
        match profile {
            SecurityProfile::Production => KeyDerivationParams::production_defaults(),
            SecurityProfile::Test => KeyDerivationParams::test_defaults(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_params_defaults() {
        let prod = KeyDerivationParams::production_defaults();
        assert_eq!(prod.memory_cost, 1024 * 1024);
        assert_eq!(prod.time_cost, 10);
        assert_eq!(prod.parallelism, 4);
        assert_eq!(prod.key_size, 32);

        let test = KeyDerivationParams::test_defaults();
        assert_eq!(test.memory_cost, 1024);
        assert_eq!(test.time_cost, 1);
        assert_eq!(test.parallelism, 1);
        assert_eq!(test.key_size, 32);
    }

    #[test]
    fn test_from_security_profile() {
        let prod_params: KeyDerivationParams = SecurityProfile::Production.into();
        assert_eq!(prod_params, KeyDerivationParams::production_defaults());

        let test_params: KeyDerivationParams = SecurityProfile::Test.into();
        assert_eq!(test_params, KeyDerivationParams::test_defaults());
    }

    #[test]
    fn test_derive_key_success() {
        let params = KeyDerivationParams::test_defaults();

        let (key, report) = params
            .derive_key(b"test_password", b"test_salt_16_bytes")
            .unwrap();
        assert_eq!(key.as_bytes().len(), 32);
        assert_eq!(report.algorithm, "Argon2id");
        assert_eq!(report.algorithm_version, "19");
        assert_eq!(report.memory_cost_kib, params.memory_cost);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let params = KeyDerivationParams::test_defaults();

        let (key1, _) = params
            .derive_key(b"test_password", b"test_salt_16_bytes")
            .unwrap();
        let (key2, _) = params
            .derive_key(b"test_password", b"test_salt_16_bytes")
            .unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let params = KeyDerivationParams::test_defaults();

        let (key1, _) = params
            .derive_key(b"password1", b"test_salt_16_bytes")
            .unwrap();
        let (key2, _) = params
            .derive_key(b"password2", b"test_salt_16_bytes")
            .unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_derive_key_invalid_parameters() {
        let invalid_params = KeyDerivationParams::new(0, 1, 1, 32);
        let result = invalid_params.derive_key(b"pw", b"test_salt_16_bytes");
        assert!(matches!(
            result,
            Err(KeyDerivationError::InvalidParameters(_))
        ));
    }
}
