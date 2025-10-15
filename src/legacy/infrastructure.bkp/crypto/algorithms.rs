//! # Cryptographic Algorithm Infrastructure
//!
//! This module provides a central place for algorithm-related exports.
//! Concrete implementations are located in separate files:
//! - `aes256_gcm.rs` - AES-256-GCM algorithm implementation
//! - `xchacha20_poly1305.rs` - XChaCha20-Poly1305 algorithm implementation  
//! - `factory.rs` - Algorithm selection and factory pattern
//!
//! All domain trait definitions are in `src/domain/services/crypto_service.rs`

// Re-export algorithm implementations for convenience
pub use super::aes256_gcm::Aes256GcmConfig;
pub use super::xchacha20_poly1305::XChaCha20Poly1305Config;
pub use super::factory::Algorithm;

#[cfg(test)]
mod tests {
    #[test]
    fn test_algorithm_exports() {
        // Verify that algorithm implementations are accessible
        use super::*;
        
        let _xchacha = Algorithm::xchacha20_poly1305();
        let _aes = Algorithm::aes256_gcm();
        assert!(true);
    }
}