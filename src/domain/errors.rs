//! # Domain Error Types
//! 
//! Comprehensive error handling for the Shadow encryption system.
//! Provides security-conscious, user-friendly error messages with actionable guidance.

use std::fmt;

/// Comprehensive error type for all domain operations
#[derive(Debug, Clone)]
pub enum DomainError {
    /// Cryptographic operation failed
    CryptographicError(CryptographicError),
    
    /// File system operation failed
    FileSystemError(FileSystemError),
    
    /// Authentication/decryption failed
    AuthenticationFailed { context: String },
    
    /// File format validation failed
    FormatError(FormatError),
    
    /// User input validation failed
    InputValidationError(InputValidationError),
    
    /// Security policy violation
    SecurityViolation(SecurityViolation),
    
    /// Resource constraint exceeded
    ResourceError(ResourceError),
    
    /// Configuration error
    ConfigurationError(ConfigurationError),
}

/// Cryptographic operation errors
#[derive(Debug, Clone)]
pub enum CryptographicError {
    /// Key derivation failed
    KeyDerivationFailed { algorithm: String },
    
    /// Encryption operation failed
    EncryptionFailed { reason: String },
    
    /// Decryption operation failed
    DecryptionFailed { reason: String },
    
    /// Random number generation failed
    RandomGenerationFailed,
    
    /// Secure memory allocation failed
    SecureMemoryAllocationFailed,
    
    /// Unsupported algorithm requested
    UnsupportedAlgorithm { algorithm_id: u16 },
    
    /// Hardware acceleration unavailable
    HardwareAccelerationUnavailable,
}

/// File system operation errors
#[derive(Debug, Clone)]
pub enum FileSystemError {
    /// File not found
    FileNotFound { path: String },
    
    /// Permission denied
    PermissionDenied { path: String },
    
    /// File already exists
    FileAlreadyExists { path: String },
    
    /// Disk space insufficient
    InsufficientDiskSpace { required: u64, available: u64 },
    
    /// I/O operation failed
    IoOperationFailed { operation: String, reason: String },
    
    /// Atomic operation failed
    AtomicOperationFailed { operation: String },
    
    /// Backup creation failed
    BackupFailed { reason: String },
}

/// File format validation errors
#[derive(Debug, Clone)]
pub enum FormatError {
    /// Invalid magic number or header
    InvalidHeader { reason: String },
    
    /// Header parsing failed
    HeaderParsingFailed { field: String, reason: String },
    
    /// Unsupported file version
    UnsupportedVersion { version: u16, max_supported: u16 },
    
    /// Corrupted file data
    CorruptedData { location: String },
    
    /// Missing required field
    MissingRequiredField { field: String },
}

/// User input validation errors
#[derive(Debug, Clone)]
pub enum InputValidationError {
    /// Password validation failed
    InvalidPassword { reason: String },
    
    /// File path validation failed
    InvalidPath { path: String, reason: String },
    
    /// Command argument validation failed
    InvalidArgument { argument: String, reason: String },
    
    /// Batch operation limit exceeded
    BatchLimitExceeded { limit: usize, requested: usize },
}

/// Security policy violation errors
#[derive(Debug, Clone)]
pub enum SecurityViolation {
    /// Attempt to encrypt already encrypted file
    DoubleEncryptionAttempt { file: String },
    
    /// Filename collision limit exceeded
    FilenameCollisionLimitExceeded,
    
    /// Operation would expose sensitive information
    SensitiveInformationExposure { context: String },
    
    /// Unauthorized operation attempt
    UnauthorizedOperation { operation: String },
}

/// Resource constraint errors
#[derive(Debug, Clone)]
pub enum ResourceError {
    /// Memory allocation failed
    OutOfMemory { requested: usize },
    
    /// Operation timeout exceeded
    TimeoutExceeded { operation: String, timeout: u64 },
    
    /// Thread pool exhausted
    ThreadPoolExhausted,
    
    /// File handle limit exceeded
    FileHandleLimitExceeded,
}

/// Configuration errors
#[derive(Debug, Clone)]
pub enum ConfigurationError {
    /// Invalid configuration value
    InvalidConfigValue { key: String, value: String, reason: String },
    
    /// Missing required configuration
    MissingRequiredConfig { key: String },
    
    /// Configuration file parsing failed
    ConfigParsingFailed { reason: String },
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainError::CryptographicError(err) => write!(f, "Cryptographic error: {}", err),
            DomainError::FileSystemError(err) => write!(f, "File system error: {}", err),
            DomainError::AuthenticationFailed { context } => write!(f, "Authentication failed: {}", context),
            DomainError::FormatError(err) => write!(f, "Format error: {}", err),
            DomainError::InputValidationError(err) => write!(f, "Input validation error: {}", err),
            DomainError::SecurityViolation(err) => write!(f, "Security violation: {}", err),
            DomainError::ResourceError(err) => write!(f, "Resource error: {}", err),
            DomainError::ConfigurationError(err) => write!(f, "Configuration error: {}", err),
        }
    }
}

impl fmt::Display for CryptographicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptographicError::KeyDerivationFailed { algorithm } => 
                write!(f, "Key derivation failed for algorithm: {}", algorithm),
            CryptographicError::EncryptionFailed { reason } => 
                write!(f, "Encryption failed: {}", reason),
            CryptographicError::DecryptionFailed { reason } => 
                write!(f, "Decryption failed: {}", reason),
            CryptographicError::RandomGenerationFailed => 
                write!(f, "Random number generation failed"),
            CryptographicError::SecureMemoryAllocationFailed => 
                write!(f, "Secure memory allocation failed"),
            CryptographicError::UnsupportedAlgorithm { algorithm_id } => 
                write!(f, "Unsupported algorithm: {:#x}", algorithm_id),
            CryptographicError::HardwareAccelerationUnavailable => 
                write!(f, "Hardware acceleration unavailable"),
        }
    }
}

impl fmt::Display for FileSystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileSystemError::FileNotFound { path } => 
                write!(f, "File not found: {}", path),
            FileSystemError::PermissionDenied { path } => 
                write!(f, "Permission denied: {}", path),
            FileSystemError::FileAlreadyExists { path } => 
                write!(f, "File already exists: {}", path),
            FileSystemError::InsufficientDiskSpace { required, available } => 
                write!(f, "Insufficient disk space: {} bytes required, {} bytes available", required, available),
            FileSystemError::IoOperationFailed { operation, reason } => 
                write!(f, "I/O operation '{}' failed: {}", operation, reason),
            FileSystemError::AtomicOperationFailed { operation } => 
                write!(f, "Atomic operation '{}' failed", operation),
            FileSystemError::BackupFailed { reason } => 
                write!(f, "Backup creation failed: {}", reason),
        }
    }
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::InvalidHeader { reason } => 
                write!(f, "Invalid file header: {}", reason),
            FormatError::HeaderParsingFailed { field, reason } => 
                write!(f, "Header field '{}' parsing failed: {}", field, reason),
            FormatError::UnsupportedVersion { version, max_supported } => 
                write!(f, "Unsupported file version {} (max supported: {})", version, max_supported),
            FormatError::CorruptedData { location } => 
                write!(f, "Corrupted data at: {}", location),
            FormatError::MissingRequiredField { field } => 
                write!(f, "Missing required field: {}", field),
        }
    }
}

impl fmt::Display for InputValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputValidationError::InvalidPassword { reason } => 
                write!(f, "Invalid password: {}", reason),
            InputValidationError::InvalidPath { path, reason } => 
                write!(f, "Invalid path '{}': {}", path, reason),
            InputValidationError::InvalidArgument { argument, reason } => 
                write!(f, "Invalid argument '{}': {}", argument, reason),
            InputValidationError::BatchLimitExceeded { limit, requested } => 
                write!(f, "Batch limit exceeded: {} requested, {} maximum", requested, limit),
        }
    }
}

impl fmt::Display for SecurityViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityViolation::DoubleEncryptionAttempt { file } => 
                write!(f, "Attempt to encrypt already encrypted file: {}", file),
            SecurityViolation::FilenameCollisionLimitExceeded => 
                write!(f, "Filename collision limit exceeded during obfuscation"),
            SecurityViolation::SensitiveInformationExposure { context } => 
                write!(f, "Operation would expose sensitive information: {}", context),
            SecurityViolation::UnauthorizedOperation { operation } => 
                write!(f, "Unauthorized operation: {}", operation),
        }
    }
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceError::OutOfMemory { requested } => 
                write!(f, "Out of memory: {} bytes requested", requested),
            ResourceError::TimeoutExceeded { operation, timeout } => 
                write!(f, "Operation '{}' exceeded timeout of {} seconds", operation, timeout),
            ResourceError::ThreadPoolExhausted => 
                write!(f, "Thread pool exhausted"),
            ResourceError::FileHandleLimitExceeded => 
                write!(f, "File handle limit exceeded"),
        }
    }
}

impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigurationError::InvalidConfigValue { key, value, reason } => 
                write!(f, "Invalid config value for '{}' = '{}': {}", key, value, reason),
            ConfigurationError::MissingRequiredConfig { key } => 
                write!(f, "Missing required configuration: {}", key),
            ConfigurationError::ConfigParsingFailed { reason } => 
                write!(f, "Configuration parsing failed: {}", reason),
        }
    }
}

impl std::error::Error for DomainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Domain errors are typically leaf errors without underlying causes
        None
    }
}

/// Convenience result type for domain operations
pub type DomainResult<T> = Result<T, DomainError>;

impl DomainError {
    /// Get user-friendly error message with actionable suggestions
    pub fn user_friendly_message(&self) -> String {
        match self {
            DomainError::AuthenticationFailed { .. } => {
                "Decryption failed - this usually means an incorrect password.\n\n\
                Suggestions:\n\
                • Double-check your password (case-sensitive)\n\
                • Verify the file wasn't corrupted during transfer\n\
                • Make sure this is a valid encrypted file".to_string()
            }
            DomainError::FileSystemError(fs_err) => fs_err.user_friendly_message(),
            DomainError::FormatError(fmt_err) => fmt_err.user_friendly_message(),
            DomainError::SecurityViolation(sec_err) => sec_err.user_friendly_message(),
            DomainError::CryptographicError(crypto_err) => crypto_err.user_friendly_message(),
            DomainError::InputValidationError(input_err) => input_err.user_friendly_message(),
            DomainError::ResourceError(res_err) => res_err.user_friendly_message(),
            DomainError::ConfigurationError(cfg_err) => cfg_err.user_friendly_message(),
        }
    }

    /// Check if this error suggests a wrong password
    pub fn suggests_wrong_password(&self) -> bool {
        matches!(self, DomainError::AuthenticationFailed { .. }) ||
        matches!(self, DomainError::CryptographicError(CryptographicError::DecryptionFailed { .. }))
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(self, 
            DomainError::AuthenticationFailed { .. } |
            DomainError::FileSystemError(_) |
            DomainError::InputValidationError(_)
        )
    }

    /// Check if this error indicates potential security issue
    pub fn is_security_related(&self) -> bool {
        matches!(self, 
            DomainError::SecurityViolation(_) |
            DomainError::AuthenticationFailed { .. }
        )
    }

    /// Create an UnsupportedAlgorithm error
    pub fn unsupported_algorithm(algorithm_id: u16) -> Self {
        DomainError::CryptographicError(CryptographicError::UnsupportedAlgorithm { algorithm_id })
    }
}

// Conversion from infrastructure crypto errors to domain errors
// This allows infrastructure implementations to use domain interfaces
impl From<crate::infrastructure::crypto::errors::CryptoError> for DomainError {
    fn from(crypto_error: crate::infrastructure::crypto::errors::CryptoError) -> Self {
        use crate::infrastructure::crypto::errors::CryptoError;
        
        match crypto_error {
            CryptoError::CryptographicError(msg) => {
                DomainError::CryptographicError(CryptographicError::EncryptionFailed { reason: msg })
            }
            CryptoError::AuthenticationFailed => {
                DomainError::AuthenticationFailed { context: "Authentication failed".to_string() }
            }
            CryptoError::KeyDerivationError(msg) => {
                DomainError::CryptographicError(CryptographicError::KeyDerivationFailed { algorithm: msg })
            }
            CryptoError::UnsupportedAlgorithm(id) => {
                DomainError::CryptographicError(CryptographicError::UnsupportedAlgorithm { algorithm_id: id })
            }
            CryptoError::RandomGenerationFailed(_) => {
                DomainError::CryptographicError(CryptographicError::RandomGenerationFailed)
            }
            CryptoError::InvalidParameters(msg) => {
                DomainError::InputValidationError(crate::domain::errors::InputValidationError::InvalidArgument { 
                    argument: "crypto_parameter".to_string(), 
                    reason: msg 
                })
            }
            CryptoError::SecureMemoryError(_) => {
                DomainError::CryptographicError(CryptographicError::SecureMemoryAllocationFailed)
            }
            CryptoError::ConfigurationError(msg) => {
                DomainError::ConfigurationError(crate::domain::errors::ConfigurationError::ConfigParsingFailed { reason: msg })
            }
            // Map other crypto errors to generic cryptographic errors
            other => {
                DomainError::CryptographicError(CryptographicError::EncryptionFailed { 
                    reason: format!("Infrastructure error: {}", other) 
                })
            }
        }
    }
}

impl FileSystemError {
    pub fn user_friendly_message(&self) -> String {
        match self {
            FileSystemError::FileNotFound { path } => {
                format!("File not found: {}\n\n\
                Suggestions:\n\
                • Check the file path for typos\n\
                • Use 'ls' to verify the file exists\n\
                • Make sure you're in the correct directory", path)
            }
            FileSystemError::PermissionDenied { path } => {
                format!("Permission denied accessing: {}\n\n\
                Suggestions:\n\
                • Check file permissions with 'ls -la'\n\
                • Run with appropriate user privileges\n\
                • Verify the parent directory is writable", path)
            }
            FileSystemError::FileAlreadyExists { path } => {
                format!("Output file already exists: {}\n\n\
                Suggestions:\n\
                • Use --force flag to overwrite existing files\n\
                • Choose a different output location\n\
                • Move or rename the existing file first", path)
            }
            FileSystemError::InsufficientDiskSpace { required, available } => {
                format!("Insufficient disk space: {} bytes needed, {} bytes available\n\n\
                Suggestions:\n\
                • Free up disk space by deleting unnecessary files\n\
                • Use a different output directory with more space\n\
                • Consider compressing other files to save space", required, available)
            }
            _ => format!("File system error: {}\n\nSuggestion: Check file permissions and available disk space", self),
        }
    }
}

impl FormatError {
    pub fn user_friendly_message(&self) -> String {
        match self {
            FormatError::InvalidHeader { .. } => {
                "Invalid file format - this doesn't appear to be a valid encrypted file.\n\n\
                Suggestions:\n\
                • Make sure the file has a .shadow extension\n\
                • Check if the file was corrupted during transfer\n\
                • Verify this file was encrypted with Shadow".to_string()
            }
            FormatError::UnsupportedVersion { version, max_supported } => {
                format!("Unsupported file version {} (maximum supported: {})\n\n\
                Suggestions:\n\
                • This file may be from a newer version of Shadow\n\
                • Update to the latest version of Shadow\n\
                • Use the shadowmigrate tool to check compatibility", version, max_supported)
            }
            FormatError::CorruptedData { .. } => {
                "File appears to be corrupted or tampered with.\n\n\
                Suggestions:\n\
                • The file may be corrupted - try recovering from backup\n\
                • Verify file integrity with checksum if available\n\
                • Re-download the file if it was transferred over network".to_string()
            }
            _ => format!("File format error: {}\n\nSuggestion: Verify the file is a valid Shadow encrypted file", self),
        }
    }
}

impl SecurityViolation {
    pub fn user_friendly_message(&self) -> String {
        match self {
            SecurityViolation::DoubleEncryptionAttempt { file } => {
                format!("File '{}' is already encrypted.\n\n\
                Suggestions:\n\
                • Use 'unshadow' to decrypt first if you want to re-encrypt\n\
                • Check if you selected the correct file\n\
                • Use 'shadows' command to list encrypted files", file)
            }
            SecurityViolation::FilenameCollisionLimitExceeded => {
                "Filename obfuscation failed due to too many collisions.\n\n\
                Suggestions:\n\
                • Try encrypting files in smaller batches\n\
                • Use a different output directory\n\
                • Contact support if this persists".to_string()
            }
            _ => format!("Security violation: {}\n\nThis operation was blocked for security reasons", self),
        }
    }
}

impl CryptographicError {
    pub fn user_friendly_message(&self) -> String {
        match self {
            CryptographicError::UnsupportedAlgorithm { algorithm_id } => {
                format!("Unsupported encryption algorithm: {:#x}\n\n\
                Suggestions:\n\
                • This file may be from a newer version of Shadow\n\
                • Update to the latest version of Shadow\n\
                • Use the shadowmigrate tool to check compatibility", algorithm_id)
            }
            CryptographicError::RandomGenerationFailed => {
                "Random number generation failed.\n\n\
                Suggestions:\n\
                • This may indicate a system security issue\n\
                • Restart the application and try again\n\
                • Contact support if the problem persists".to_string()
            }
            _ => format!("Cryptographic error: {}\n\nThis indicates an internal cryptographic failure", self),
        }
    }
}

impl InputValidationError {
    pub fn user_friendly_message(&self) -> String {
        match self {
            InputValidationError::InvalidPassword { reason } => {
                format!("Password validation failed: {}\n\n\
                Suggestions:\n\
                • Use a stronger password with mixed characters\n\
                • Avoid common passwords or dictionary words\n\
                • Consider using a password manager", reason)
            }
            InputValidationError::InvalidPath { path, reason } => {
                format!("Invalid file path '{}': {}\n\n\
                Suggestions:\n\
                • Check for typos in the file path\n\
                • Use absolute paths to avoid confusion\n\
                • Ensure the path doesn't contain invalid characters", path, reason)
            }
            _ => format!("Input validation error: {}\n\nPlease check your command arguments", self),
        }
    }
}

impl ResourceError {
    pub fn user_friendly_message(&self) -> String {
        match self {
            ResourceError::OutOfMemory { requested } => {
                format!("Out of memory: {} bytes requested\n\n\
                Suggestions:\n\
                • Close other applications to free memory\n\
                • Process files in smaller batches\n\
                • Use a system with more available RAM", requested)
            }
            ResourceError::TimeoutExceeded { operation, timeout } => {
                format!("Operation '{}' exceeded {} second timeout\n\n\
                Suggestions:\n\
                • The file may be very large - increase timeout if possible\n\
                • Check system performance and disk speed\n\
                • Try processing smaller files first", operation, timeout)
            }
            _ => format!("Resource constraint error: {}\n\nThe system lacks sufficient resources", self),
        }
    }
}

impl ConfigurationError {
    pub fn user_friendly_message(&self) -> String {
        match self {
            ConfigurationError::InvalidConfigValue { key, value, reason } => {
                format!("Invalid configuration '{}' = '{}': {}\n\n\
                Suggestions:\n\
                • Check the configuration documentation\n\
                • Reset to default values if unsure\n\
                • Verify the value format is correct", key, value, reason)
            }
            ConfigurationError::MissingRequiredConfig { key } => {
                format!("Missing required configuration: {}\n\n\
                Suggestions:\n\
                • Add the required configuration setting\n\
                • Check the documentation for default values\n\
                • Run with --help to see configuration options", key)
            }
            _ => format!("Configuration error: {}\n\nPlease check your configuration settings", self),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_error_display() {
        let error = DomainError::AuthenticationFailed {
            context: "wrong password".to_string(),
        };
        assert_eq!(error.to_string(), "Authentication failed: wrong password");
    }

    #[test]
    fn test_cryptographic_error_display() {
        let error = CryptographicError::UnsupportedAlgorithm { algorithm_id: 0x1234 };
        assert_eq!(error.to_string(), "Unsupported algorithm: 0x1234");
    }

    #[test]
    fn test_file_system_error_display() {
        let error = FileSystemError::InsufficientDiskSpace {
            required: 1024,
            available: 512,
        };
        assert_eq!(error.to_string(), "Insufficient disk space: 1024 bytes required, 512 bytes available");
    }

    #[test]
    fn test_authentication_failed_user_friendly_message() {
        let error = DomainError::AuthenticationFailed {
            context: "decryption failed".to_string(),
        };
        let message = error.user_friendly_message();
        assert!(message.contains("incorrect password"));
        assert!(message.contains("Double-check your password"));
        assert!(message.contains("case-sensitive"));
    }

    #[test]
    fn test_file_not_found_user_friendly_message() {
        let error = DomainError::FileSystemError(FileSystemError::FileNotFound {
            path: "/path/to/missing.txt".to_string(),
        });
        let message = error.user_friendly_message();
        assert!(message.contains("/path/to/missing.txt"));
        assert!(message.contains("Check the file path for typos"));
        assert!(message.contains("Use 'ls' to verify"));
    }

    #[test]
    fn test_permission_denied_user_friendly_message() {
        let fs_error = FileSystemError::PermissionDenied {
            path: "/protected/file.txt".to_string(),
        };
        let message = fs_error.user_friendly_message();
        assert!(message.contains("Permission denied"));
        assert!(message.contains("/protected/file.txt"));
        assert!(message.contains("Check file permissions"));
        assert!(message.contains("ls -la"));
    }

    #[test]
    fn test_double_encryption_user_friendly_message() {
        let error = DomainError::SecurityViolation(SecurityViolation::DoubleEncryptionAttempt {
            file: "already_encrypted.shadow".to_string(),
        });
        let message = error.user_friendly_message();
        assert!(message.contains("already encrypted"));
        assert!(message.contains("already_encrypted.shadow"));
        assert!(message.contains("Use 'unshadow' to decrypt first"));
    }

    #[test]
    fn test_unsupported_algorithm_user_friendly_message() {
        let error = DomainError::CryptographicError(CryptographicError::UnsupportedAlgorithm {
            algorithm_id: 0x9999,
        });
        let message = error.user_friendly_message();
        assert!(message.contains("0x9999"));
        assert!(message.contains("newer version of Shadow"));
        assert!(message.contains("shadowmigrate tool"));
    }

    #[test]
    fn test_suggests_wrong_password() {
        let auth_error = DomainError::AuthenticationFailed {
            context: "test".to_string(),
        };
        assert!(auth_error.suggests_wrong_password());

        let decrypt_error = DomainError::CryptographicError(CryptographicError::DecryptionFailed {
            reason: "test".to_string(),
        });
        assert!(decrypt_error.suggests_wrong_password());

        let file_error = DomainError::FileSystemError(FileSystemError::FileNotFound {
            path: "test".to_string(),
        });
        assert!(!file_error.suggests_wrong_password());
    }

    #[test]
    fn test_is_recoverable() {
        let recoverable_errors = vec![
            DomainError::AuthenticationFailed { context: "test".to_string() },
            DomainError::FileSystemError(FileSystemError::FileNotFound { path: "test".to_string() }),
            DomainError::InputValidationError(InputValidationError::InvalidPassword { reason: "test".to_string() }),
        ];

        for error in recoverable_errors {
            assert!(error.is_recoverable(), "Error should be recoverable: {}", error);
        }

        let non_recoverable_error = DomainError::CryptographicError(CryptographicError::RandomGenerationFailed);
        assert!(!non_recoverable_error.is_recoverable());
    }

    #[test]
    fn test_is_security_related() {
        let security_errors = vec![
            DomainError::SecurityViolation(SecurityViolation::DoubleEncryptionAttempt { file: "test".to_string() }),
            DomainError::AuthenticationFailed { context: "test".to_string() },
        ];

        for error in security_errors {
            assert!(error.is_security_related(), "Error should be security-related: {}", error);
        }

        let non_security_error = DomainError::FileSystemError(FileSystemError::FileNotFound { path: "test".to_string() });
        assert!(!non_security_error.is_security_related());
    }

    #[test]
    fn test_insufficient_disk_space_message() {
        let error = FileSystemError::InsufficientDiskSpace {
            required: 1000000,
            available: 500000,
        };
        let message = error.user_friendly_message();
        assert!(message.contains("1000000 bytes needed"));
        assert!(message.contains("500000 bytes available"));
        assert!(message.contains("Free up disk space"));
    }

    #[test]
    fn test_invalid_file_format_message() {
        let error = FormatError::InvalidHeader {
            reason: "magic number mismatch".to_string(),
        };
        let message = error.user_friendly_message();
        assert!(message.contains("doesn't appear to be a valid encrypted file"));
        assert!(message.contains(".shadow extension"));
        assert!(message.contains("encrypted with Shadow"));
    }

    #[test]
    fn test_configuration_error_messages() {
        let error = ConfigurationError::InvalidConfigValue {
            key: "algorithm".to_string(),
            value: "invalid_algo".to_string(),
            reason: "unknown algorithm".to_string(),
        };
        let message = error.user_friendly_message();
        assert!(message.contains("'algorithm' = 'invalid_algo'"));
        assert!(message.contains("unknown algorithm"));
        assert!(message.contains("configuration documentation"));
    }
}