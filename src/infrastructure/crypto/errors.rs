//! # Cryptographic Error Types
//!
//! Comprehensive error handling for cryptographic operations,
//! providing detailed error information with security-conscious messaging.

use std::fmt;

/// Comprehensive error type for cryptographic operations
///
/// This enum covers all possible failure modes in cryptographic operations
/// while being careful not to leak sensitive information in error messages.
#[derive(Debug)]
pub enum CryptoError {
    /// Cryptographic operation failed with details
    CryptographicError(String),
    
    /// File system operation failed
    FileSystemError(std::io::Error),
    
    /// Authentication failed during decryption (wrong password/corrupted data)
    AuthenticationFailed,
    
    /// File header parsing failed
    HeaderParsingError(String),
    
    /// Key derivation operation failed
    KeyDerivationError(String),
    
    /// File format is invalid or unrecognized
    InvalidFileFormat,
    
    /// Specified file was not found
    FileNotFound(String),
    
    /// Algorithm identifier is not supported
    UnsupportedAlgorithm(u16),
    
    /// Random number generation failed
    RandomGenerationFailed(String),
    
    /// Parameter validation failed
    InvalidParameters(String),
    
    /// Secure memory allocation failed
    SecureMemoryError(String),
    
    /// Configuration validation failed
    ConfigurationError(String),
    
    /// Nonce generation failed
    NonceGenerationFailed(String),
    
    /// Salt generation failed  
    SaltGenerationFailed(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::CryptographicError(msg) => {
                write!(f, "Cryptographic operation failed: {}", msg)
            },
            CryptoError::FileSystemError(err) => {
                write!(f, "File system error: {}", err)
            },
            CryptoError::AuthenticationFailed => {
                write!(f, "Authentication failed - verify password and file integrity")
            },
            CryptoError::HeaderParsingError(msg) => {
                write!(f, "File header parsing failed: {}", msg)
            },
            CryptoError::KeyDerivationError(msg) => {
                write!(f, "Key derivation failed: {}", msg)
            },
            CryptoError::InvalidFileFormat => {
                write!(f, "Invalid or unrecognized file format")
            },
            CryptoError::FileNotFound(path) => {
                write!(f, "File not found: {}", path)
            },
            CryptoError::UnsupportedAlgorithm(id) => {
                write!(f, "Unsupported algorithm identifier: {:#x}", id)
            },
            CryptoError::RandomGenerationFailed(details) => {
                write!(f, "Random number generation failed: {}", details)
            },
            CryptoError::InvalidParameters(msg) => {
                write!(f, "Invalid parameters: {}", msg)
            },
            CryptoError::SecureMemoryError(msg) => {
                write!(f, "Secure memory operation failed: {}", msg)
            },
            CryptoError::ConfigurationError(msg) => {
                write!(f, "Configuration error: {}", msg)
            },
            CryptoError::NonceGenerationFailed(msg) => {
                write!(f, "Nonce generation failed: {}", msg)
            },
            CryptoError::SaltGenerationFailed(msg) => {
                write!(f, "Salt generation failed: {}", msg)
            },
        }
    }
}

impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CryptoError::FileSystemError(err) => Some(err),
            _ => None,
        }
    }
}

// Convenient conversions from common error types
impl From<std::io::Error> for CryptoError {
    fn from(err: std::io::Error) -> Self {
        CryptoError::FileSystemError(err)
    }
}

impl From<getrandom::Error> for CryptoError {
    fn from(err: getrandom::Error) -> Self {
        CryptoError::RandomGenerationFailed(err.to_string())
    }
}

/// Result type alias for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

// Conversion from domain errors to infrastructure errors
// This allows infrastructure layer to work with domain layer abstractions
impl From<crate::domain::errors::DomainError> for CryptoError {
    fn from(domain_error: crate::domain::errors::DomainError) -> Self {
        use crate::domain::errors::{DomainError, CryptographicError};
        
        match domain_error {
            DomainError::CryptographicError(crypto_err) => {
                match crypto_err {
                    CryptographicError::KeyDerivationFailed { algorithm } => {
                        CryptoError::KeyDerivationError(format!("Key derivation failed for {}", algorithm))
                    }
                    CryptographicError::EncryptionFailed { reason } => {
                        CryptoError::CryptographicError(format!("Encryption failed: {}", reason))
                    }
                    CryptographicError::DecryptionFailed { reason } => {
                        CryptoError::CryptographicError(format!("Decryption failed: {}", reason))
                    }
                    CryptographicError::RandomGenerationFailed => {
                        CryptoError::RandomGenerationFailed("Random generation failed".to_string())
                    }
                    CryptographicError::UnsupportedAlgorithm { algorithm_id } => {
                        CryptoError::UnsupportedAlgorithm(algorithm_id)
                    }
                    CryptographicError::SecureMemoryAllocationFailed => {
                        CryptoError::SecureMemoryError("Secure memory allocation failed".to_string())
                    }
                    CryptographicError::HardwareAccelerationUnavailable => {
                        CryptoError::ConfigurationError("Hardware acceleration unavailable".to_string())
                    }
                }
            }
            DomainError::AuthenticationFailed { .. } => {
                CryptoError::AuthenticationFailed
            }
            // For other domain errors, map to generic cryptographic error
            other => {
                CryptoError::CryptographicError(format!("Domain error: {}", other))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = CryptoError::AuthenticationFailed;
        assert_eq!(
            error.to_string(),
            "Authentication failed - verify password and file integrity"
        );
    }

    #[test]
    fn test_error_from_io() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "test file");
        let crypto_error = CryptoError::from(io_error);
        
        match crypto_error {
            CryptoError::FileSystemError(_) => {}, // Expected
            _ => panic!("Expected FileSystemError"),
        }
    }

    #[test]
    fn test_unsupported_algorithm_display() {
        let error = CryptoError::UnsupportedAlgorithm(0x1234);
        assert!(error.to_string().contains("0x1234"));
    }
}