//! # Algorithm Selection and Factory
//!
//! This module provides an enum-based approach for selecting and creating
//! cryptographic algorithm configurations, solving trait object limitations.
//!
//! ## Factory Pattern Design
//!
//! The `Algorithm` enum implements all cryptographic traits and can be used
//! directly instead of trait objects to avoid object safety issues. This design
//! provides:
//!
//! - **Type Safety**: Compile-time algorithm selection and dispatch
//! - **Performance**: Zero-cost abstractions with monomorphization
//! - **Extensibility**: New algorithms require only enum variant additions
//! - **Testability**: Each algorithm can be tested in isolation
//!
//! ## Adding New Algorithms
//!
//! To add a new algorithm:
//! 1. Create algorithm implementation following the three-trait pattern
//! 2. Add new variant to `Algorithm` enum
//! 3. Update all match statements to handle new variant
//! 4. Add to `supported_algorithms()` list
//! 5. Update `AlgorithmId` enum in domain layer
//!
//! See `docs/specs/ALGORITHM_IMPLEMENTATION_GUIDE.md` for detailed instructions.
//!
//! ## Cross-Algorithm Compatibility
//!
//! All algorithms share the same trait interface, ensuring that:
//! - Domain services work with any supported algorithm
//! - Files encrypted with different algorithms remain compatible
//! - Algorithm choice is determined by file header during decryption
//! - New algorithms don't break existing functionality

use super::{AlgorithmId, CryptographicAlgorithm, EncryptionResult, KeyMaterial};
use crate::domain::errors::DomainError;
use crate::infrastructure::crypto::{
    aes256_gcm::Aes256GcmConfig,
    xchacha20_poly1305::XChaCha20Poly1305Config,
};

/// Enumeration of all supported cryptographic algorithms
/// 
/// This enum implements the CryptographicAlgorithm trait and can be used
/// directly instead of trait objects to avoid object safety issues.
#[derive(Debug, Clone)]
pub enum Algorithm {
    XChaCha20Poly1305(XChaCha20Poly1305Config),
    Aes256Gcm(Aes256GcmConfig),
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::XChaCha20Poly1305(XChaCha20Poly1305Config::production_config())
    }
}

impl Algorithm {

    /// Create algorithm by ID with production parameters
    pub fn from_id(id: AlgorithmId) -> Self {
        match id {
            AlgorithmId::XChaCha20Poly1305 => {
                Self::XChaCha20Poly1305(XChaCha20Poly1305Config::production_config())
            }
            AlgorithmId::AesGcm256 => {
                Self::Aes256Gcm(Aes256GcmConfig::production_config())
            }
        }
    }

    /// Create test algorithm by ID (fast parameters)
    pub fn test_from_id(id: AlgorithmId) -> Self {
        match id {
            AlgorithmId::XChaCha20Poly1305 => {
                Self::XChaCha20Poly1305(XChaCha20Poly1305Config::test_config())
            }
            AlgorithmId::AesGcm256 => {
                Self::Aes256Gcm(Aes256GcmConfig::test_config())
            }
        }
    }

    /// Create XChaCha20-Poly1305 with production parameters
    pub fn xchacha20_poly1305() -> Self {
        Self::XChaCha20Poly1305(XChaCha20Poly1305Config::production_config())
    }

    /// Create AES-256-GCM with production parameters  
    pub fn aes256_gcm() -> Self {
        Self::Aes256Gcm(Aes256GcmConfig::production_config())
    }

    /// Create XChaCha20-Poly1305 with test parameters
    pub fn xchacha20_poly1305_test() -> Self {
        Self::XChaCha20Poly1305(XChaCha20Poly1305Config::test_config())
    }

    /// Create AES-256-GCM with test parameters
    pub fn aes256_gcm_test() -> Self {
        Self::Aes256Gcm(Aes256GcmConfig::test_config())
    }

    /// Get list of all supported algorithm IDs
    pub fn supported_algorithms() -> Vec<AlgorithmId> {
        vec![AlgorithmId::XChaCha20Poly1305, AlgorithmId::AesGcm256]
    }

    /// Check if an algorithm ID is supported
    pub fn is_supported(id: AlgorithmId) -> bool {
        matches!(id, AlgorithmId::XChaCha20Poly1305 | AlgorithmId::AesGcm256)
    }
}

impl CryptographicAlgorithm for Algorithm {
    fn encrypt(
        &self,
        plaintext: &[u8],
        key_material: &KeyMaterial,
    ) -> Result<EncryptionResult, DomainError> {
        match self {
            Algorithm::XChaCha20Poly1305(config) => config.encrypt(plaintext, key_material),
            Algorithm::Aes256Gcm(config) => config.encrypt(plaintext, key_material),
        }
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        key_material: &KeyMaterial,
    ) -> Result<Vec<u8>, DomainError> {
        match self {
            Algorithm::XChaCha20Poly1305(config) => config.decrypt(ciphertext, nonce, key_material),
            Algorithm::Aes256Gcm(config) => config.decrypt(ciphertext, nonce, key_material),
        }
    }

    fn test_config() -> Self {
        // Return the recommended algorithm with test config
        // This maintains interface compatibility while providing sensible defaults
        Algorithm::test_from_id(AlgorithmId::recommended())
    }

    fn production_config() -> Self {
        // Return the recommended algorithm with production config
        Algorithm::from_id(AlgorithmId::recommended())
    }
}

impl super::KeyDerivationConfig for Algorithm {
    fn derive_key_material(&self, password: &str, salt: &[u8]) -> Result<KeyMaterial, DomainError> {
        match self {
            Algorithm::XChaCha20Poly1305(config) => config.derive_key_material(password, salt),
            Algorithm::Aes256Gcm(config) => config.derive_key_material(password, salt),
        }
    }

    fn salt_length(&self) -> usize {
        match self {
            Algorithm::XChaCha20Poly1305(config) => config.salt_length(),
            Algorithm::Aes256Gcm(config) => config.salt_length(),
        }
    }

    fn generate_salt(&self) -> Result<Vec<u8>, DomainError> {
        match self {
            Algorithm::XChaCha20Poly1305(config) => config.generate_salt(),
            Algorithm::Aes256Gcm(config) => config.generate_salt(),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Algorithm::XChaCha20Poly1305(config) => config.name(),
            Algorithm::Aes256Gcm(config) => config.name(),
        }
    }
}

impl super::EncryptionConfig for Algorithm {
    fn key_size(&self) -> usize {
        match self {
            Algorithm::XChaCha20Poly1305(config) => config.key_size(),
            Algorithm::Aes256Gcm(config) => config.key_size(),
        }
    }

    fn nonce_size(&self) -> usize {
        match self {
            Algorithm::XChaCha20Poly1305(config) => config.nonce_size(),
            Algorithm::Aes256Gcm(config) => config.nonce_size(),
        }
    }

    fn algorithm_id(&self) -> AlgorithmId {
        match self {
            Algorithm::XChaCha20Poly1305(config) => config.algorithm_id(),
            Algorithm::Aes256Gcm(config) => config.algorithm_id(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{EncryptionConfig, KeyDerivationConfig, CryptographicAlgorithm};

    #[test]
    fn test_default_algorithm() {
        let algo = Algorithm::default();
        assert_eq!(algo.algorithm_id(), AlgorithmId::XChaCha20Poly1305);
    }

    #[test]
    fn test_from_id() {
        let xchacha = Algorithm::from_id(AlgorithmId::XChaCha20Poly1305);
        assert_eq!(xchacha.algorithm_id(), AlgorithmId::XChaCha20Poly1305);

        let aes = Algorithm::from_id(AlgorithmId::AesGcm256);
        assert_eq!(aes.algorithm_id(), AlgorithmId::AesGcm256);
    }

    #[test]
    fn test_test_from_id() {
        let xchacha = Algorithm::test_from_id(AlgorithmId::XChaCha20Poly1305);
        assert_eq!(xchacha.algorithm_id(), AlgorithmId::XChaCha20Poly1305);

        let aes = Algorithm::test_from_id(AlgorithmId::AesGcm256);
        assert_eq!(aes.algorithm_id(), AlgorithmId::AesGcm256);
    }

    #[test]
    fn test_supported_algorithms() {
        let supported = Algorithm::supported_algorithms();
        assert_eq!(supported.len(), 2);
        assert!(supported.contains(&AlgorithmId::XChaCha20Poly1305));
        assert!(supported.contains(&AlgorithmId::AesGcm256));
    }

    #[test]
    fn test_is_supported() {
        assert!(Algorithm::is_supported(AlgorithmId::XChaCha20Poly1305));
        assert!(Algorithm::is_supported(AlgorithmId::AesGcm256));
    }

    #[test]
    fn test_convenience_constructors() {
        let xchacha = Algorithm::xchacha20_poly1305();
        assert_eq!(xchacha.algorithm_id(), AlgorithmId::XChaCha20Poly1305);

        let aes = Algorithm::aes256_gcm();
        assert_eq!(aes.algorithm_id(), AlgorithmId::AesGcm256);

        let xchacha_test = Algorithm::xchacha20_poly1305_test();
        assert_eq!(xchacha_test.algorithm_id(), AlgorithmId::XChaCha20Poly1305);

        let aes_test = Algorithm::aes256_gcm_test();
        assert_eq!(aes_test.algorithm_id(), AlgorithmId::AesGcm256);
    }

    #[test]
    fn test_cross_algorithm_compatibility() {
        // Test that both algorithms work with the same interface
        let algorithms = vec![
            Algorithm::xchacha20_poly1305_test(),
            Algorithm::aes256_gcm_test(),
        ];

        for algo in algorithms {
            let salt = algo.generate_salt().unwrap();
            let key = algo.derive_key_material("test_password", &salt).unwrap();
            let plaintext = b"Hello, world!";

            let encrypted = algo.encrypt(plaintext, &key).unwrap();
            let decrypted = algo.decrypt(&encrypted.ciphertext, &encrypted.nonce, &key).unwrap();

            assert_eq!(plaintext, decrypted.as_slice());
        }
    }
}