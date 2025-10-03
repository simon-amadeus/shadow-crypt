//! V2 format operation dispatch
//! 
//! This module provides operation dispatch for Shadow V2 file format

use crate::shared::errors::CryptoError;
use crate::shared::algorithms::Algorithm;
use std::path::Path;

/// Dispatch operations for Shadow V2 files
pub struct DispatchV2;

impl Default for DispatchV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl DispatchV2 {
    /// Create a new V2 operation dispatcher
    pub fn new() -> Self {
        Self
    }

    /// Get the supported algorithms for V2 format
    pub fn supported_algorithms() -> Vec<Algorithm> {
        vec![
            Algorithm::AES256GCM,
            Algorithm::XChaCha20Poly1305,
        ]
    }

    /// Check if an algorithm is supported in V2 format
    pub fn supports_algorithm(algorithm: Algorithm) -> bool {
        Self::supported_algorithms().contains(&algorithm)
    }

    /// Validate that a file operation is supported
    pub fn validate_operation(
        _file_path: &Path,
        algorithm: Algorithm,
    ) -> Result<(), CryptoError> {
        if !Self::supports_algorithm(algorithm) {
            return Err(CryptoError::CryptographicError(
                format!("Algorithm {:?} not supported in V2 format", algorithm)
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_supported_algorithms() {
        let algorithms = DispatchV2::supported_algorithms();
        assert!(algorithms.contains(&Algorithm::AES256GCM));
        assert!(algorithms.contains(&Algorithm::XChaCha20Poly1305));
    }

    #[test]
    fn test_algorithm_support_check() {
        assert!(DispatchV2::supports_algorithm(Algorithm::AES256GCM));
        assert!(DispatchV2::supports_algorithm(Algorithm::XChaCha20Poly1305));
    }

    #[test]
    fn test_operation_validation() {
        let dummy_path = Path::new("test.txt");
        
        // Test supported algorithms
        assert!(DispatchV2::validate_operation(dummy_path, Algorithm::AES256GCM).is_ok());
        assert!(DispatchV2::validate_operation(dummy_path, Algorithm::XChaCha20Poly1305).is_ok());
    }
}