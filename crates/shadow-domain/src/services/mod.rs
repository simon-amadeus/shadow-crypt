//! # Domain Services
//!
//! Core business services that orchestrate domain operations.

pub mod crypto_algorithm;
pub mod crypto_config;
pub mod crypto_service;
// pub mod encryption_service;  // Temporarily disabled - implementation moved to application layer
pub mod decryption_service;
pub mod listing_service;
pub mod migration_service;
pub mod file_detector;
pub mod password_service;
pub mod tlv_parser;
pub mod header_analysis;

// Re-export key traits from the new crypto service
pub use crypto_service::{
    CryptographicAlgorithm, 
    KeyDerivationConfig, 
    EncryptionConfig, 
    EncryptionResult, 
    ConfigProvider,
    DefaultConfigProvider
};

// Re-export file detection services
pub use file_detector::{FileDetector, FileFormat};

// Re-export encryption services  
// pub use encryption_service::{EncryptionService, EncryptionOptions, EncryptionResult as ServiceEncryptionResult, BatchResult};

// Re-export decryption services
pub use decryption_service::{DecryptionService, DecryptionOptions, DecryptionResult};

// Re-export listing services
pub use listing_service::{ListingService, DirectoryListing, EncryptedFileInfo};

// Re-export password services
pub use password_service::{PasswordVerificationService, PasswordVerificationError};

// Legacy re-exports for compatibility during transition
pub use crypto_algorithm::{CryptographicAlgorithm as LegacyCryptographicAlgorithm, KeyDerivationConfig as LegacyKeyDerivationConfig, EncryptionConfig as LegacyEncryptionConfig, EncryptionResult as LegacyEncryptionResult, CryptoResult};

// Infrastructure abstraction traits - implemented by infrastructure crate
use crate::errors::DomainError;

/// Abstract TLV serialization interface - prevents domain dependency on infrastructure
pub trait TlvSerializer {
    fn serialize_header(&self, header: &crate::entities::tlv_header::TlvHeader) -> Result<Vec<u8>, DomainError>;
    fn deserialize_header(&self, data: &[u8]) -> Result<crate::entities::tlv_header::TlvHeader, DomainError>;
}

/// Abstract progress reporting interface - prevents domain dependency on infrastructure
pub trait ProgressReporter {
    fn report(&self, message: &str);
    fn report_progress(&self, message: &str, current: usize, total: usize);
}

/// Simple stub implementation for compilation - replaced by infrastructure
pub struct StubProgressReporter;

impl ProgressReporter for StubProgressReporter {
    fn report(&self, _message: &str) {
        // Stub implementation - replaced by infrastructure
    }
    
    fn report_progress(&self, _message: &str, _current: usize, _total: usize) {
        // Stub implementation - replaced by infrastructure
    }
}

/// Simple stub implementation for compilation - replaced by infrastructure
pub struct StubTlvSerializer;

impl TlvSerializer for StubTlvSerializer {
    fn serialize_header(&self, _header: &crate::entities::tlv_header::TlvHeader) -> Result<Vec<u8>, DomainError> {
        // Stub implementation - replaced by infrastructure
        Ok(vec![])
    }
    
    fn deserialize_header(&self, _data: &[u8]) -> Result<crate::entities::tlv_header::TlvHeader, DomainError> {
        // Stub implementation - replaced by infrastructure
        Err(DomainError::ConfigurationError(crate::errors::ConfigurationError::ConfigParsingFailed {
            reason: "Using stub implementation".to_string(),
        }))
    }
}

/// Abstract algorithm factory interface - prevents domain dependency on infrastructure
// TODO: Make CryptographicAlgorithm object-safe or redesign factory pattern
// pub trait CryptoAlgorithmFactory {
//     fn create_algorithm(&self, algorithm_id: &crate::entities::AlgorithmId) -> Result<Box<dyn CryptographicAlgorithm>, DomainError>;
// }

// Integration tests module
#[cfg(test)]
mod integration_tests;