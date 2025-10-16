// shadow-core/src/errors.rs
// Error types for the Shadow encryption system
// All errors are pure values with no side effects

use thiserror::Error;

/// Cryptographic operation errors - pure, no side effects in creation/handling
#[derive(Debug, Error, Clone, PartialEq)]
pub enum CryptoError {
    #[error("Key derivation failed")]
    KeyDerivation,
    
    #[error("Encryption failed")]
    Encryption,
    
    #[error("Decryption failed")]
    Decryption,
    
    #[error("Invalid nonce size: expected {expected}, got {actual}")]
    InvalidNonce { expected: usize, actual: usize },
    
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKey { expected: usize, actual: usize },
    
    #[error("Invalid salt size: expected {expected}, got {actual}")]
    InvalidSalt { expected: usize, actual: usize },
    
    #[error("Random number generation failed")]
    RandomGeneration,
    
    #[error("HKDF key derivation failed")]
    HkdfDerivation,
    
    #[error("Authentication tag verification failed")]
    AuthenticationFailed,
}

/// Validation errors for input data - pure, no side effects
#[derive(Debug, Error, Clone, PartialEq)]
pub enum ValidationError {
    #[error("Empty password provided")]
    EmptyPassword,
    
    #[error("Empty file content")]
    EmptyFile,
    
    #[error("Invalid header format")]
    InvalidHeader,
    
    #[error("Invalid magic bytes: expected {expected:?}, got {actual:?}")]
    InvalidMagic { expected: [u8; 8], actual: [u8; 8] },
    
    #[error("Unsupported algorithm ID: {0}")]
    UnsupportedAlgorithm(u8),
    
    #[error("Invalid obfuscation flag: {0}")]
    InvalidObfuscationFlag(u8),
    
    #[error("Content hash mismatch: expected {expected:x?}, got {actual:x?}")]
    ContentHashMismatch { expected: [u8; 32], actual: [u8; 32] },
    
    #[error("Invalid filename data")]
    InvalidFilenameData,
    
    #[error("Header too short: expected at least {expected} bytes, got {actual}")]
    HeaderTooShort { expected: usize, actual: usize },
    
    #[error("Invalid file size: {0}")]
    InvalidFileSize(u64),
}

/// Serialization and deserialization errors - pure, no side effects
#[derive(Debug, Error, Clone, PartialEq)]
pub enum SerializationError {
    #[error("Failed to serialize header")]
    HeaderSerialization,
    
    #[error("Failed to deserialize header")]
    HeaderDeserialization,
    
    #[error("Invalid data length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    
    #[error("Buffer overflow: trying to write {requested} bytes, but only {available} available")]
    BufferOverflow { requested: usize, available: usize },
    
    #[error("Buffer underflow: trying to read {requested} bytes, but only {available} available")]
    BufferUnderflow { requested: usize, available: usize },
    
    #[error("Invalid UTF-8 string")]
    InvalidUtf8,
    
    #[error("Filename too long: {length} bytes, maximum is {max}")]
    FilenameTooLong { length: usize, max: usize },
}

/// Aggregated error type that can contain any core error
#[derive(Debug, Error, Clone, PartialEq)]
pub enum CoreError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_error_display() {
        let err = CryptoError::KeyDerivation;
        assert_eq!(err.to_string(), "Key derivation failed");
    }

    #[test]
    fn test_crypto_error_invalid_nonce() {
        let err = CryptoError::InvalidNonce { expected: 24, actual: 12 };
        assert_eq!(err.to_string(), "Invalid nonce size: expected 24, got 12");
    }

    #[test]
    fn test_validation_error_display() {
        let err = ValidationError::EmptyPassword;
        assert_eq!(err.to_string(), "Empty password provided");
    }

    #[test]
    fn test_validation_error_magic_bytes() {
        let expected = *b"SHADOW01";
        let actual = *b"BADMAGIC";
        let err = ValidationError::InvalidMagic { expected, actual };
        assert!(err.to_string().contains("Invalid magic bytes"));
    }

    #[test]
    fn test_serialization_error_display() {
        let err = SerializationError::HeaderSerialization;
        assert_eq!(err.to_string(), "Failed to serialize header");
    }

    #[test]
    fn test_serialization_error_invalid_length() {
        let err = SerializationError::InvalidLength { expected: 100, actual: 50 };
        assert_eq!(err.to_string(), "Invalid data length: expected 100, got 50");
    }

    #[test]
    fn test_core_error_from_crypto() {
        let crypto_err = CryptoError::Encryption;
        let core_err: CoreError = crypto_err.into();
        match core_err {
            CoreError::Crypto(CryptoError::Encryption) => {},
            _ => panic!("Expected crypto encryption error"),
        }
    }

    #[test]
    fn test_core_error_from_validation() {
        let validation_err = ValidationError::EmptyFile;
        let core_err: CoreError = validation_err.into();
        match core_err {
            CoreError::Validation(ValidationError::EmptyFile) => {},
            _ => panic!("Expected validation empty file error"),
        }
    }

    #[test]
    fn test_core_error_from_serialization() {
        let serialization_err = SerializationError::HeaderDeserialization;
        let core_err: CoreError = serialization_err.into();
        match core_err {
            CoreError::Serialization(SerializationError::HeaderDeserialization) => {},
            _ => panic!("Expected serialization header deserialization error"),
        }
    }

    #[test]
    fn test_error_equality() {
        let err1 = CryptoError::KeyDerivation;
        let err2 = CryptoError::KeyDerivation;
        let err3 = CryptoError::Encryption;
        
        assert_eq!(err1, err2);
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_error_clone() {
        let original = ValidationError::InvalidHeader;
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }
}