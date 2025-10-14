//! # Simplified Domain Services
//!
//! Essential domain service abstractions - keep it simple!
//! These traits define what the domain needs without over-engineering.

use std::path::Path;

use crate::domain::shared::{
    AlgorithmId, 
    plaintext_file::PlaintextFile,
    encrypted_file::EncryptedFile,
    path::{PlaintextFilePath, EncryptedFilePath},
};
use crate::domain::errors::DomainError;

/// Result type for domain operations
pub type DomainResult<T> = Result<T, DomainError>;

// ============================================================================
// PASSWORD HANDLING
// ============================================================================

/// Simple password operations - no need for separate repository/service
pub trait PasswordHandler: Send + Sync {
    /// Prompt for password (hidden input)
    fn prompt_password(&self, prompt: &str) -> DomainResult<String>;
    
    /// Prompt for password with confirmation
    fn prompt_password_with_confirmation(&self, prompt: &str) -> DomainResult<String>;
}

// ============================================================================
// CRYPTOGRAPHIC OPERATIONS  
// ============================================================================

/// Simple crypto abstraction for the domain
/// Infrastructure selects and implements specific algorithms
pub trait CryptoProvider: Send + Sync {
    /// Encrypt plaintext file to encrypted file
    fn encrypt(
        &self,
        plaintext: &PlaintextFile,
        password: &str,
        algorithm: AlgorithmId,
    ) -> DomainResult<EncryptedFile>;

    /// Decrypt encrypted file to plaintext file  
    fn decrypt(
        &self,
        encrypted: &EncryptedFile,
        password: &str,
    ) -> DomainResult<PlaintextFile>;

    /// Verify password can decrypt file (quick check)
    fn verify_password(
        &self,
        encrypted: &EncryptedFile,
        password: &str,
    ) -> DomainResult<bool>;
}

// ============================================================================
// FILE OPERATIONS
// ============================================================================

/// Simple file operations - atomic transactions built-in
pub trait FileHandler: Send + Sync {
    /// Read plaintext file from filesystem
    fn read_plaintext(&self, path: &PlaintextFilePath) -> DomainResult<PlaintextFile>;
    
    /// Read encrypted file from filesystem
    fn read_encrypted(&self, path: &EncryptedFilePath) -> DomainResult<EncryptedFile>;
    
    /// Write plaintext file to filesystem
    fn write_plaintext(&self, file: &PlaintextFile, path: &PlaintextFilePath) -> DomainResult<()>;
    
    /// Write encrypted file to filesystem  
    fn write_encrypted(&self, file: &EncryptedFile, path: &EncryptedFilePath) -> DomainResult<()>;
    
    /// Delete file securely
    fn delete_secure(&self, path: &Path) -> DomainResult<()>;
    
    /// Detect file type and create typed path
    fn detect_file_type(&self, path: &Path) -> DomainResult<TypedFilePath>;
}

/// Either plaintext or encrypted file path
#[derive(Debug, Clone)]
pub enum TypedFilePath {
    Plaintext(PlaintextFilePath),
    Encrypted(EncryptedFilePath),
}

// ============================================================================
// HIGH-LEVEL OPERATIONS
// ============================================================================

/// Options for encryption
#[derive(Debug, Clone)]
pub struct EncryptionOptions {
    pub algorithm: AlgorithmId,
    pub remove_source: bool,
    pub verify_integrity: bool,
}

/// Options for decryption
#[derive(Debug, Clone)]
pub struct DecryptionOptions {
    pub remove_source: bool,
    pub verify_integrity: bool,
}

/// Information about an encrypted file
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: EncryptedFilePath,
    pub original_filename: Option<String>,
    pub algorithm: AlgorithmId,
    pub size: u64,
    pub password_valid: bool,
}

/// Complete encryption/decryption service
/// Coordinates between crypto, file, and password operations
pub trait ShadowService: Send + Sync {
    /// Encrypt a file with user interaction
    fn encrypt_file(
        &self,
        source: &PlaintextFilePath,
        options: &EncryptionOptions,
    ) -> DomainResult<EncryptedFilePath>;

    /// Decrypt a file with user interaction
    fn decrypt_file(
        &self,
        source: &EncryptedFilePath,
        options: &DecryptionOptions,
    ) -> DomainResult<PlaintextFilePath>;

    /// List encrypted files in directory
    fn list_directory(&self, directory: &Path) -> DomainResult<Vec<FileInfo>>;

    /// Get information about a single encrypted file
    fn inspect_file(&self, path: &EncryptedFilePath) -> DomainResult<FileInfo>;
}