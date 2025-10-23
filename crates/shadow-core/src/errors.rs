use std::{error::Error, fmt::Display};

#[derive(Debug)]
pub enum HeaderError {
    InsufficientBytes,
    InvalidData,
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderError::InsufficientBytes => write!(f, "Insufficient bytes to read header"),
            HeaderError::InvalidData => write!(f, "Invalid header data"),
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
