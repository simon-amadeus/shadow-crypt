// shadow-core/src/v1/crypto.rs
// V1-specific cryptographic algorithms, parameters, and operations
// Contains all cryptographic choices specific to Shadow format v1.0

use argon2::{Algorithm, Argon2, Params, Version};
use crate::crypto::keys::derive_key as generic_derive_key;
use crate::errors::CryptoError;
use crate::memory::{SecureKey, SecureString};
use sha2::{Digest, Sha256};

/// Security profiles defining cryptographic parameter sets for Shadow v1.0
///
/// Provides two distinct configurations aligned with KISS and YAGNI principles:
/// - Test: Fast parameters for development and testing
/// - Production: Strong parameters for real-world security
///
/// These profiles are specific to v1.0 format. Future format versions may
/// define different parameter sets or even different algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    /// Fast parameters for development/testing only
    ///
    /// **WARNING: These parameters provide minimal security and should NEVER be used in production**
    ///
    /// Parameters:
    /// - Memory Cost: 64 KiB
    /// - Time Cost: 1 iteration  
    /// - Parallelism: 1 thread
    Test,

    /// Production-grade security parameters
    ///
    /// These parameters provide strong security suitable for protecting real data.
    /// Based on current cryptographic recommendations as of 2025.
    ///
    /// Parameters:
    /// - Memory Cost: 1 GiB (1,048,576 KiB)
    /// - Time Cost: 5 iterations
    /// - Parallelism: 4 threads
    Production,
}

impl SecurityProfile {
    /// Get Argon2 parameters for this security profile
    ///
    /// Returns properly configured Argon2 parameters that match the
    /// security requirements for each profile.
    ///
    /// # Panics
    ///
    /// Panics if the hardcoded parameters are invalid (should never happen
    /// in practice as these are well-tested parameter combinations).
    pub fn argon2_params(&self) -> Params {
        match self {
            SecurityProfile::Test => {
                // Fast parameters - suitable for testing only
                Params::new(
                    64,   // m_cost: 64 KiB memory
                    1,    // t_cost: 1 iteration
                    1,    // p_cost: 1 thread
                    None, // output_len: use default (32 bytes)
                )
                .expect("Test Argon2 parameters should be valid")
            }
            SecurityProfile::Production => {
                // Strong parameters - suitable for production
                Params::new(
                    1_048_576, // m_cost: 1 GiB memory
                    5,         // t_cost: 5 iterations
                    4,         // p_cost: 4 threads
                    None,      // output_len: use default (32 bytes)
                )
                .expect("Production Argon2 parameters should be valid")
            }
        }
    }

    /// Create a configured Argon2 instance for this security profile
    ///
    /// Returns an Argon2 instance using Argon2id algorithm with parameters
    /// appropriate for this security profile.
    pub fn create_argon2(&self) -> Argon2<'static> {
        let params = self.argon2_params();
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    }

    /// Get a human-readable description of this security profile
    ///
    /// Useful for logging and user feedback about which security
    /// profile is being used.
    pub fn description(&self) -> &'static str {
        match self {
            SecurityProfile::Test => "Fast (Test-only)",
            SecurityProfile::Production => "Secure (Production)",
        }
    }

    /// Check if this profile is suitable for production use
    ///
    /// Returns `false` for Test profile to help prevent accidental
    /// use of weak parameters in production environments.
    pub fn is_production_safe(&self) -> bool {
        match self {
            SecurityProfile::Test => false,
            SecurityProfile::Production => true,
        }
    }
}

/// V1-specific key derivation using configured security profile
///
/// This is a convenience wrapper around the generic derive_key function
/// that uses v1-specific Argon2 parameters based on the security profile.
///
/// # Parameters
///
/// * `password` - The password to derive the key from
/// * `salt` - 16-byte salt for key derivation
/// * `profile` - V1 security profile determining Argon2 parameters
pub fn derive_key(
    password: &SecureString,
    salt: &[u8; 16],
    profile: SecurityProfile,
) -> Result<SecureKey, CryptoError> {
    let argon2 = profile.create_argon2();
    generic_derive_key(password, salt, &argon2)
}

/// V1-specific content hashing using SHA-256
///
/// This function is part of the v1 format specification.
/// Future versions may use different hash functions.
///
/// Pure function - deterministic with same inputs
pub fn hash_content(content: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(content);
    hasher.finalize().into()
}

/// V1-specific cryptographic algorithm identifiers
///
/// These constants define which algorithms are supported in v1.0 format.
/// Future versions may add new algorithms or deprecate existing ones.
pub mod algorithms {
    /// XChaCha20-Poly1305 AEAD cipher
    /// This is the primary (and currently only) algorithm supported in v1.0
    pub const XCHACHA20_POLY1305: u8 = 0x01;
}

/// V1-specific cryptographic parameters and sizes
///
/// These constants define the cryptographic parameters used throughout
/// the v1.0 format implementation.
pub mod params {
    /// XChaCha20 key size in bytes
    pub const KEY_SIZE: usize = 32;
    
    /// XChaCha20 nonce size in bytes  
    pub const NONCE_SIZE: usize = 24;
    
    /// Argon2id salt size in bytes
    pub const SALT_SIZE: usize = 16;
    
    /// SHA-256 hash size in bytes
    pub const HASH_SIZE: usize = 32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_profile_descriptions() {
        assert_eq!(SecurityProfile::Test.description(), "Fast (Test-only)");
        assert_eq!(SecurityProfile::Production.description(), "Secure (Production)");
    }

    #[test]
    fn test_production_safety_check() {
        assert!(!SecurityProfile::Test.is_production_safe());
        assert!(SecurityProfile::Production.is_production_safe());
    }

    #[test]
    fn test_argon2_instance_creation() {
        let _test_argon2 = SecurityProfile::Test.create_argon2();
        let _prod_argon2 = SecurityProfile::Production.create_argon2();

        // Verify they're different instances with different parameters
        let test_params = SecurityProfile::Test.argon2_params();
        let prod_params = SecurityProfile::Production.argon2_params();

        assert_ne!(test_params.m_cost(), prod_params.m_cost());
        assert_ne!(test_params.t_cost(), prod_params.t_cost());
    }

    #[test]
    fn test_v1_derive_key_basic() {
        let password = SecureString::new("test_password".to_string());
        let salt = [1u8; 16];

        let result = derive_key(&password, &salt, SecurityProfile::Test);
        assert!(result.is_ok());
    }

    #[test]
    fn test_v1_derive_key_deterministic() {
        let password = SecureString::new("test_password".to_string());
        let salt = [1u8; 16];

        let key1 = derive_key(&password, &salt, SecurityProfile::Test).unwrap();
        let key2 = derive_key(&password, &salt, SecurityProfile::Test).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_v1_hash_content_deterministic() {
        let content = b"Hello, World!";

        let hash1 = hash_content(content);
        let hash2 = hash_content(content);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_v1_hash_content_different_inputs() {
        let content1 = b"Hello, World!";
        let content2 = b"Hello, World?";

        let hash1 = hash_content(content1);
        let hash2 = hash_content(content2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_algorithm_constants() {
        assert_eq!(algorithms::XCHACHA20_POLY1305, 0x01);
    }

    #[test]
    fn test_param_constants() {
        assert_eq!(params::KEY_SIZE, 32);
        assert_eq!(params::NONCE_SIZE, 24);
        assert_eq!(params::SALT_SIZE, 16);
        assert_eq!(params::HASH_SIZE, 32);
    }
}