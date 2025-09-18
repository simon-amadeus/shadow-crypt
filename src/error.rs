use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Cryptographic operation failed: {0}")]
    CryptographicError(String),
    
    #[error("File system error: {0}")]
    FileSystemError(#[from] std::io::Error),
    
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("Header parsing failed: {0}")]
    HeaderParsingError(String),
    
    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),
    
    #[error("Filename collision limit exceeded")]
    TooManyCollisions,
    
    #[error("Partial decryption not supported for this file type")]
    PartialDecryptionNotSupported,
    
    #[error("Operation interrupted: {context}")]
    OperationInterrupted { context: String },
    
    #[error("Batch processing failed: {0:?}")]
    BatchProcessingFailed(Vec<EncryptionError>),
    
    #[error("Editor failed to run")]
    EditorFailed,
    
    #[error("Invalid file format")]
    InvalidFileFormat,
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),
    
    #[error("Base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),
}
