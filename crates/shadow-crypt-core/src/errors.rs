use std::{error::Error, fmt::Display};

#[derive(Debug)]
pub enum HeaderError {
    InsufficientBytes,
    InvalidData,
    FilenameTooLong,
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderError::InsufficientBytes => write!(f, "Insufficient bytes to read header"),
            HeaderError::InvalidData => write!(f, "Invalid header data"),
            HeaderError::FilenameTooLong => {
                write!(f, "Encrypted filename is too long to fit in the header")
            }
        }
    }
}

impl std::error::Error for HeaderError {}

#[derive(Debug)]
pub enum KeyDerivationError {
    InvalidParameters(String),
    DerivationFailed(String),
}

impl std::fmt::Display for KeyDerivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyDerivationError::InvalidParameters(msg) => write!(f, "Invalid parameters: {}", msg),
            KeyDerivationError::DerivationFailed(msg) => write!(f, "Derivation failed: {}", msg),
        }
    }
}

impl std::error::Error for KeyDerivationError {}

#[derive(Debug)]
pub enum CryptError {
    EncryptionError(String),
    DecryptionError(String),
}

impl Display for CryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            CryptError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
        }
    }
}

impl Error for CryptError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_header_error_display() {
        let insufficient = HeaderError::InsufficientBytes;
        assert_eq!(
            format!("{}", insufficient),
            "Insufficient bytes to read header"
        );

        let invalid = HeaderError::InvalidData;
        assert_eq!(format!("{}", invalid), "Invalid header data");
    }

    #[test]
    fn test_header_error_is_error_trait() {
        let error = HeaderError::InsufficientBytes;
        // Just ensure it implements Error trait (compilation test)
        let _error_trait: &dyn Error = &error;
    }

    #[test]
    fn test_key_derivation_error_display() {
        let invalid = KeyDerivationError::InvalidParameters("test msg".to_string());
        assert_eq!(format!("{}", invalid), "Invalid parameters: test msg");

        let failed = KeyDerivationError::DerivationFailed("test msg".to_string());
        assert_eq!(format!("{}", failed), "Derivation failed: test msg");
    }

    #[test]
    fn test_key_derivation_error_is_error_trait() {
        let error = KeyDerivationError::InvalidParameters("test".to_string());
        let _error_trait: &dyn Error = &error;
    }

    #[test]
    fn test_crypt_error_display() {
        let encrypt = CryptError::EncryptionError("test msg".to_string());
        assert_eq!(format!("{}", encrypt), "Encryption error: test msg");

        let decrypt = CryptError::DecryptionError("test msg".to_string());
        assert_eq!(format!("{}", decrypt), "Decryption error: test msg");
    }

    #[test]
    fn test_crypt_error_is_error_trait() {
        let error = CryptError::EncryptionError("test".to_string());
        let _error_trait: &dyn Error = &error;
    }
}
