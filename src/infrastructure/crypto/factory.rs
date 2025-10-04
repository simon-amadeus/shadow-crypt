//! # Algorithm Selection and Factory
//!
//! This module provides an enum-based approach for selecting and creating
//! cryptographic algorithm configurations, solving trait object limitations.

use super::{AlgorithmId, CryptographicAlgorithm, EncryptionResult, KeyMaterial};
use crate::infrastructure::crypto::{
    aes256_gcm::Aes256GcmConfig,
    xchacha20_poly1305::XChaCha20Poly1305Config,
    CryptoResult,
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

impl Algorithm {
    /// Create the default algorithm (XChaCha20-Poly1305 with production parameters)
    pub fn default() -> Self {
        Self::XChaCha20Poly1305(XChaCha20Poly1305Config::production_config())
    }

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
        Self::supported_algorithms().contains(&id)
    }
}

impl CryptographicAlgorithm for Algorithm {
    fn encrypt(
        &self,
        plaintext: &[u8],
        key_material: &KeyMaterial,
    ) -> CryptoResult<EncryptionResult> {
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
    ) -> CryptoResult<Vec<u8>> {
        match self {
            Algorithm::XChaCha20Poly1305(config) => config.decrypt(ciphertext, nonce, key_material),
            Algorithm::Aes256Gcm(config) => config.decrypt(ciphertext, nonce, key_material),
        }
    }

    fn test_config() -> Self {
        Self::default() // Use default for this static method
    }

    fn production_config() -> Self {
        Self::default()
    }
}

impl super::KeyDerivationConfig for Algorithm {
    fn derive_key_material(&self, password: &str, salt: &[u8]) -> CryptoResult<KeyMaterial> {
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

        let aes = Algorithm::from_id(AlgorithmId::Aes256Gcm);
        assert_eq!(aes.algorithm_id(), AlgorithmId::Aes256Gcm);
    }

    #[test]
    fn test_test_from_id() {
        let xchacha = Algorithm::test_from_id(AlgorithmId::XChaCha20Poly1305);
        assert_eq!(xchacha.algorithm_id(), AlgorithmId::XChaCha20Poly1305);

        let aes = Algorithm::test_from_id(AlgorithmId::Aes256Gcm);
        assert_eq!(aes.algorithm_id(), AlgorithmId::Aes256Gcm);
    }

    #[test]
    fn test_supported_algorithms() {
        let supported = Algorithm::supported_algorithms();
        assert_eq!(supported.len(), 2);
        assert!(supported.contains(&AlgorithmId::XChaCha20Poly1305));
        assert!(supported.contains(&AlgorithmId::Aes256Gcm));
    }

    #[test]
    fn test_is_supported() {
        assert!(Algorithm::is_supported(AlgorithmId::XChaCha20Poly1305));
        assert!(Algorithm::is_supported(AlgorithmId::Aes256Gcm));
    }

    #[test]
    fn test_convenience_constructors() {
        let xchacha = Algorithm::xchacha20_poly1305();
        assert_eq!(xchacha.algorithm_id(), AlgorithmId::XChaCha20Poly1305);

        let aes = Algorithm::aes256_gcm();
        assert_eq!(aes.algorithm_id(), AlgorithmId::Aes256Gcm);

        let xchacha_test = Algorithm::xchacha20_poly1305_test();
        assert_eq!(xchacha_test.algorithm_id(), AlgorithmId::XChaCha20Poly1305);

        let aes_test = Algorithm::aes256_gcm_test();
        assert_eq!(aes_test.algorithm_id(), AlgorithmId::Aes256Gcm);
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