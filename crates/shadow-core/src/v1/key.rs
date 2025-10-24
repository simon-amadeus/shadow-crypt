use crate::profile::SecurityProfile;

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

    fn production_defaults() -> Self {
        Self {
            memory_cost: 4 * 1024 * 1024, // 4,194,304 KiB (4 GiB)
            time_cost: 10,                // 10 iterations
            parallelism: 4,               // 4 threads
            key_size: 32,                 // 32 bytes (256 bits)
        }
    }

    fn test_defaults() -> Self {
        Self {
            memory_cost: 1 * 1024, // 1,024 KiB (1 MiB)
            time_cost: 1,          // 1 iteration
            parallelism: 1,        // 1 thread
            key_size: 32,          // 32 bytes (256 bits)
        }
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
        assert_eq!(prod.memory_cost, 4 * 1024 * 1024);
        assert_eq!(prod.time_cost, 10);
        assert_eq!(prod.parallelism, 4);
        assert_eq!(prod.key_size, 32);

        let test = KeyDerivationParams::test_defaults();
        assert_eq!(test.memory_cost, 1 * 1024);
        assert_eq!(test.time_cost, 1);
        assert_eq!(test.parallelism, 1);
        assert_eq!(test.key_size, 32);
    }

    #[test]
    fn test_from_security_profile() {
        let prod_params: KeyDerivationParams = SecurityProfile::Production.into();
        let expected_prod = KeyDerivationParams::production_defaults();
        assert_eq!(prod_params, expected_prod);

        let test_params: KeyDerivationParams = SecurityProfile::Test.into();
        let expected_test = KeyDerivationParams::test_defaults();
        assert_eq!(test_params, expected_test);
    }
}
