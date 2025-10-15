//! # Infrastructure Error Types
//! 
//! Infrastructure-specific error handling for file system, terminal,
//! and other external system interactions.

use crate::domain::errors::{DomainError, FileSystemError, ConfigurationError, ResourceError};
use std::{fmt, io};

/// Infrastructure layer specific errors
#[derive(Debug)]
pub enum InfrastructureError {
    /// File system operation failed
    FileSystem(FileSystemError),
    
    /// Terminal interaction failed
    Terminal(TerminalError),
    
    /// Cryptographic provider failed
    CryptoProvider(CryptoProviderError),
    
    /// TLV serialization failed
    Serialization(SerializationError),
    
    /// Configuration loading failed
    Configuration(ConfigurationError),
    
    /// Resource constraint exceeded
    Resource(ResourceError),
}

/// Terminal interaction errors
#[derive(Debug, Clone)]
pub enum TerminalError {
    /// Password input failed
    PasswordInputFailed { reason: String },
    
    /// Terminal not available (non-interactive mode)
    TerminalNotAvailable,
    
    /// User cancelled operation
    UserCancelled,
    
    /// Progress display failed
    ProgressDisplayFailed { reason: String },
    
    /// Terminal formatting error
    FormattingError { reason: String },
}

/// Cryptographic provider errors
#[derive(Debug, Clone)]
pub enum CryptoProviderError {
    /// Initialization failed
    InitializationFailed { provider: String, reason: String },
    
    /// Provider not available
    ProviderNotAvailable { provider: String },
    
    /// Configuration invalid
    InvalidConfiguration { setting: String, reason: String },
    
    /// Operation failed
    OperationFailed { operation: String, reason: String },
}

/// TLV serialization/deserialization errors
#[derive(Debug, Clone)]
pub enum SerializationError {
    /// Buffer too small for operation
    BufferTooSmall { required: usize, available: usize },
    
    /// Invalid TLV structure
    InvalidTlvStructure { reason: String },
    
    /// Unknown field type
    UnknownFieldType { field_type: u16 },
    
    /// Serialization failed
    SerializationFailed { field: String, reason: String },
    
    /// Deserialization failed
    DeserializationFailed { field: String, reason: String },
    
    /// Version mismatch
    VersionMismatch { expected: u16, found: u16 },
}

impl fmt::Display for InfrastructureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InfrastructureError::FileSystem(err) => write!(f, "File system error: {}", err),
            InfrastructureError::Terminal(err) => write!(f, "Terminal error: {}", err),
            InfrastructureError::CryptoProvider(err) => write!(f, "Crypto provider error: {}", err),
            InfrastructureError::Serialization(err) => write!(f, "Serialization error: {}", err),
            InfrastructureError::Configuration(err) => write!(f, "Configuration error: {}", err),
            InfrastructureError::Resource(err) => write!(f, "Resource error: {}", err),
        }
    }
}

impl fmt::Display for TerminalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TerminalError::PasswordInputFailed { reason } => 
                write!(f, "Password input failed: {}", reason),
            TerminalError::TerminalNotAvailable => 
                write!(f, "Terminal not available for interactive input"),
            TerminalError::UserCancelled => 
                write!(f, "Operation cancelled by user"),
            TerminalError::ProgressDisplayFailed { reason } => 
                write!(f, "Progress display failed: {}", reason),
            TerminalError::FormattingError { reason } => 
                write!(f, "Terminal formatting error: {}", reason),
        }
    }
}

impl fmt::Display for CryptoProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoProviderError::InitializationFailed { provider, reason } => 
                write!(f, "Crypto provider '{}' initialization failed: {}", provider, reason),
            CryptoProviderError::ProviderNotAvailable { provider } => 
                write!(f, "Crypto provider '{}' not available", provider),
            CryptoProviderError::InvalidConfiguration { setting, reason } => 
                write!(f, "Invalid crypto configuration '{}': {}", setting, reason),
            CryptoProviderError::OperationFailed { operation, reason } => 
                write!(f, "Crypto operation '{}' failed: {}", operation, reason),
        }
    }
}

impl fmt::Display for SerializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerializationError::BufferTooSmall { required, available } => 
                write!(f, "Buffer too small: {} bytes required, {} available", required, available),
            SerializationError::InvalidTlvStructure { reason } => 
                write!(f, "Invalid TLV structure: {}", reason),
            SerializationError::UnknownFieldType { field_type } => 
                write!(f, "Unknown TLV field type: {:#x}", field_type),
            SerializationError::SerializationFailed { field, reason } => 
                write!(f, "Serialization of field '{}' failed: {}", field, reason),
            SerializationError::DeserializationFailed { field, reason } => 
                write!(f, "Deserialization of field '{}' failed: {}", field, reason),
            SerializationError::VersionMismatch { expected, found } => 
                write!(f, "Version mismatch: expected {}, found {}", expected, found),
        }
    }
}

impl std::error::Error for InfrastructureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None // Infrastructure errors are typically leaf errors
    }
}

// Conversion implementations for error propagation
impl From<io::Error> for InfrastructureError {
    fn from(error: io::Error) -> Self {
        let fs_error = match error.kind() {
            io::ErrorKind::NotFound => FileSystemError::FileNotFound {
                path: "unknown".to_string(), // Path context should be provided by caller
            },
            io::ErrorKind::PermissionDenied => FileSystemError::PermissionDenied {
                path: "unknown".to_string(),
            },
            io::ErrorKind::AlreadyExists => FileSystemError::FileAlreadyExists {
                path: "unknown".to_string(),
            },
            _ => FileSystemError::IoOperationFailed {
                operation: "unknown".to_string(),
                reason: error.to_string(),
            },
        };
        InfrastructureError::FileSystem(fs_error)
    }
}

impl From<FileSystemError> for InfrastructureError {
    fn from(error: FileSystemError) -> Self {
        InfrastructureError::FileSystem(error)
    }
}

impl From<TerminalError> for InfrastructureError {
    fn from(error: TerminalError) -> Self {
        InfrastructureError::Terminal(error)
    }
}

impl From<CryptoProviderError> for InfrastructureError {
    fn from(error: CryptoProviderError) -> Self {
        InfrastructureError::CryptoProvider(error)
    }
}

impl From<SerializationError> for InfrastructureError {
    fn from(error: SerializationError) -> Self {
        InfrastructureError::Serialization(error)
    }
}

impl From<ConfigurationError> for InfrastructureError {
    fn from(error: ConfigurationError) -> Self {
        InfrastructureError::Configuration(error)
    }
}

impl From<ResourceError> for InfrastructureError {
    fn from(error: ResourceError) -> Self {
        InfrastructureError::Resource(error)
    }
}

// Convert infrastructure errors to domain errors
impl From<InfrastructureError> for DomainError {
    fn from(error: InfrastructureError) -> Self {
        match error {
            InfrastructureError::FileSystem(fs_err) => DomainError::FileSystemError(fs_err),
            InfrastructureError::Configuration(cfg_err) => DomainError::ConfigurationError(cfg_err),
            InfrastructureError::Resource(res_err) => DomainError::ResourceError(res_err),
            // Map infrastructure-specific errors to appropriate domain errors
            InfrastructureError::Terminal(term_err) => match term_err {
                TerminalError::UserCancelled => DomainError::InputValidationError(
                    crate::domain::errors::InputValidationError::InvalidArgument {
                        argument: "operation".to_string(),
                        reason: "cancelled by user".to_string(),
                    }
                ),
                _ => DomainError::ConfigurationError(ConfigurationError::ConfigParsingFailed {
                    reason: format!("Terminal error: {}", term_err),
                }),
            },
            InfrastructureError::CryptoProvider(crypto_err) => DomainError::CryptographicError(
                crate::domain::errors::CryptographicError::EncryptionFailed {
                    reason: format!("Provider error: {}", crypto_err),
                }
            ),
            InfrastructureError::Serialization(ser_err) => DomainError::FormatError(
                crate::domain::errors::FormatError::HeaderParsingFailed {
                    field: "serialization".to_string(),
                    reason: ser_err.to_string(),
                }
            ),
        }
    }
}

impl InfrastructureError {
    /// Get user-friendly error message with actionable suggestions
    pub fn user_friendly_message(&self) -> String {
        match self {
            InfrastructureError::FileSystem(fs_err) => fs_err.user_friendly_message(),
            InfrastructureError::Terminal(term_err) => term_err.user_friendly_message(),
            InfrastructureError::CryptoProvider(crypto_err) => crypto_err.user_friendly_message(),
            InfrastructureError::Serialization(ser_err) => ser_err.user_friendly_message(),
            InfrastructureError::Configuration(cfg_err) => cfg_err.user_friendly_message(),
            InfrastructureError::Resource(res_err) => res_err.user_friendly_message(),
        }
    }
}

impl TerminalError {
    pub fn user_friendly_message(&self) -> String {
        match self {
            TerminalError::PasswordInputFailed { .. } => {
                "Failed to read password input.\n\n\
                Suggestions:\n\
                • Make sure you're running in an interactive terminal\n\
                • Check terminal permissions and capabilities\n\
                • Try running from a different terminal if possible".to_string()
            }
            TerminalError::TerminalNotAvailable => {
                "Interactive terminal not available.\n\n\
                Suggestions:\n\
                • Run from an interactive terminal session\n\
                • Avoid running through automation that lacks terminal access\n\
                • Use environment variables for non-interactive authentication if supported".to_string()
            }
            TerminalError::UserCancelled => {
                "Operation cancelled by user.\n\n\
                Note: You can restart the operation at any time.".to_string()
            }
            _ => format!("Terminal error: {}\n\nTry running from a different terminal", self),
        }
    }
}

impl CryptoProviderError {
    pub fn user_friendly_message(&self) -> String {
        match self {
            CryptoProviderError::ProviderNotAvailable { provider } => {
                format!("Cryptographic provider '{}' is not available.\n\n\
                Suggestions:\n\
                • Install required cryptographic libraries\n\
                • Check system security modules are functioning\n\
                • Try using a different algorithm if available", provider)
            }
            CryptoProviderError::InitializationFailed { provider, .. } => {
                format!("Failed to initialize cryptographic provider '{}'.\n\n\
                Suggestions:\n\
                • Check system cryptographic capabilities\n\
                • Verify hardware security modules are accessible\n\
                • Contact support if using specialized crypto hardware", provider)
            }
            _ => format!("Cryptographic provider error: {}\n\nThis indicates a system-level crypto issue", self),
        }
    }
}

impl SerializationError {
    pub fn user_friendly_message(&self) -> String {
        match self {
            SerializationError::VersionMismatch { expected, found } => {
                format!("File version mismatch: expected {}, found {}\n\n\
                Suggestions:\n\
                • This file may be from a different version of Shadow\n\
                • Use shadowmigrate tool to check compatibility\n\
                • Update to the latest version if possible", expected, found)
            }
            SerializationError::InvalidTlvStructure { .. } => {
                "File structure is corrupted or invalid.\n\n\
                Suggestions:\n\
                • The file may have been corrupted during transfer\n\
                • Try recovering from a backup if available\n\
                • Verify file integrity with checksums".to_string()
            }
            _ => format!("File format error: {}\n\nThe file structure appears to be corrupted", self),
        }
    }
}

/// Convenience result type for infrastructure operations
pub type InfrastructureResult<T> = Result<T, InfrastructureError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_io_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "test file not found");
        let infra_err: InfrastructureError = io_err.into();
        
        match infra_err {
            InfrastructureError::FileSystem(FileSystemError::FileNotFound { .. }) => {},
            _ => panic!("Expected FileNotFound error"),
        }
    }

    #[test]
    fn test_infrastructure_to_domain_conversion() {
        let term_err = TerminalError::UserCancelled;
        let infra_err = InfrastructureError::Terminal(term_err);
        let domain_err: DomainError = infra_err.into();
        
        match domain_err {
            DomainError::InputValidationError(_) => {},
            _ => panic!("Expected InputValidationError"),
        }
    }

    #[test]
    fn test_terminal_error_user_friendly_message() {
        let error = TerminalError::TerminalNotAvailable;
        let message = error.user_friendly_message();
        assert!(message.contains("Interactive terminal not available"));
        assert!(message.contains("Run from an interactive terminal"));
    }

    #[test]
    fn test_crypto_provider_error_user_friendly_message() {
        let error = CryptoProviderError::ProviderNotAvailable {
            provider: "XChaCha20".to_string(),
        };
        let message = error.user_friendly_message();
        assert!(message.contains("XChaCha20"));
        assert!(message.contains("not available"));
        assert!(message.contains("Install required cryptographic libraries"));
    }

    #[test]
    fn test_serialization_error_user_friendly_message() {
        let error = SerializationError::VersionMismatch {
            expected: 1,
            found: 2,
        };
        let message = error.user_friendly_message();
        assert!(message.contains("expected 1, found 2"));
        assert!(message.contains("different version of Shadow"));
        assert!(message.contains("shadowmigrate tool"));
    }
}