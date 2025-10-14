//! # Core Domain Service Traits
//!
//! This module defines the essential service abstractions that the domain layer needs
//! for file encryption, decryption, and listing operations. These traits represent
//! pure business capabilities without any infrastructure concerns.
//!
//! ## Architecture Principles
//!
//! These traits follow clean architecture and domain-driven design principles:
//! - Domain defines what it needs through interfaces
//! - Infrastructure implements these interfaces  
//! - Application layer orchestrates domain services
//! - No dependency on external concerns (files, crypto libraries, etc.)
//!
//! ## Bidirectional Design
//!
//! The system is designed for bidirectional operations:
//! - Encryption: PlaintextFile (in-memory) → EncryptedFile (in-memory)
//! - Decryption: EncryptedFile (in-memory) → PlaintextFile (in-memory)
//! - File I/O: FileHandler manages atomic transactions between filesystem and entities

use std::path::Path;
use std::time::Duration;

use crate::domain::entities::{
    AlgorithmId, 
    plaintext_file::PlaintextFile,
    encrypted_file::EncryptedFile,
    path::{PlaintextFilePath, EncryptedFilePath},
};
use crate::domain::errors::DomainError;

/// Result type for domain service operations
pub type ServiceResult<T> = Result<T, DomainError>;

// ============================================================================
// ENCRYPTION DOMAIN SERVICES
// ============================================================================

/// Options for file encryption operations
#[derive(Debug, Clone)]
pub struct EncryptionOptions {
    /// Encryption algorithm to use
    pub algorithm: AlgorithmId,
    /// Whether to verify integrity after encryption
    pub verify_integrity: bool,
    /// Optional custom output filename (None = auto-generate)
    pub output_filename: Option<String>,
}

/// Result of a file encryption operation
#[derive(Debug, Clone)]
pub struct EncryptionResult {
    /// Original plaintext file path
    pub source_path: PlaintextFilePath,
    /// Suggested output path for the encrypted file
    pub suggested_output_path: EncryptedFilePath,
    /// Algorithm used for encryption
    pub algorithm: AlgorithmId,
    /// Time taken for the encryption operation
    pub duration: Duration,
    /// Content hash of the original file (for duplicate detection)
    pub content_hash: String,
}

/// Core encryption service abstraction
/// 
/// Represents the domain's need to encrypt files. This service operates on
/// in-memory entities (PlaintextFile → EncryptedFile) and does not handle file I/O.
/// File I/O is managed separately by FileHandler with atomic transactions.
pub trait EncryptionService: Send + Sync {
    /// Encrypt plaintext content to encrypted content (in-memory operation)
    /// 
    /// Takes a PlaintextFile entity and transforms it into an EncryptedFile entity.
    /// Does not perform any file I/O - that's handled by FileHandler.
    fn encrypt(
        &self,
        plaintext_file: &PlaintextFile,
        password: &str,
        options: &EncryptionOptions,
    ) -> ServiceResult<EncryptedFile>;

    /// Estimate encryption time and output size for planning
    fn estimate_encryption(
        &self,
        file_size: u64,
        algorithm: AlgorithmId,
    ) -> ServiceResult<EncryptionEstimate>;
}

/// Estimation for encryption operations
#[derive(Debug, Clone)]
pub struct EncryptionEstimate {
    /// Estimated time for encryption
    pub estimated_duration: Duration,
    /// Estimated size of encrypted output
    pub estimated_output_size: u64,
    /// Memory requirements for the operation
    pub memory_requirement: u64,
}

// ============================================================================
// DECRYPTION DOMAIN SERVICES  
// ============================================================================

/// Options for file decryption operations
#[derive(Debug, Clone)]
pub struct DecryptionOptions {
    /// Whether to verify integrity before decryption
    pub verify_integrity: bool,
    /// Optional custom output filename (None = use original filename from metadata)
    pub output_filename: Option<String>,
}

/// Result of a file decryption operation
#[derive(Debug, Clone)]
pub struct DecryptionResult {
    /// Original encrypted file path
    pub source_path: EncryptedFilePath,
    /// Suggested output path for the decrypted file
    pub suggested_output_path: PlaintextFilePath,
    /// Original filename recovered from metadata
    pub original_filename: String,
    /// Algorithm that was used for encryption
    pub algorithm: AlgorithmId,
    /// Time taken for the decryption operation
    pub duration: Duration,
}

/// Core decryption service abstraction
///
/// Represents the domain's need to decrypt files. This service operates on
/// in-memory entities (EncryptedFile → PlaintextFile) and does not handle file I/O.
/// File I/O is managed separately by FileHandler with atomic transactions.
pub trait DecryptionService: Send + Sync {
    /// Decrypt encrypted content to plaintext content (in-memory operation)
    /// 
    /// Takes an EncryptedFile entity and transforms it into a PlaintextFile entity.
    /// Does not perform any file I/O - that's handled by FileHandler.
    fn decrypt(
        &self,
        encrypted_file: &EncryptedFile,
        password: &str,
        options: &DecryptionOptions,
    ) -> ServiceResult<PlaintextFile>;

    /// Verify that a password can decrypt a file without full decryption
    /// 
    /// Performs a quick verification by attempting to decrypt a small portion
    /// or by verifying authentication tags without extracting full content.
    fn verify_password(
        &self,
        encrypted_file: &EncryptedFile,
        password: &str,
    ) -> ServiceResult<bool>;

    /// Extract metadata from encrypted file without full decryption
    /// 
    /// Retrieves header information and metadata that can be accessed
    /// without decrypting the entire file content.
    fn extract_metadata(
        &self,
        encrypted_file: &EncryptedFile,
        password: &str,
    ) -> ServiceResult<EncryptedFileMetadata>;
}

/// Metadata that can be extracted from encrypted files
#[derive(Debug, Clone)]
pub struct EncryptedFileMetadata {
    /// Original filename before encryption
    pub original_filename: String,
    /// Algorithm used for encryption
    pub algorithm: AlgorithmId,
    /// File format version
    pub version: u16,
    /// Content hash (if available)
    pub content_hash: Option<String>,
    /// Timestamp when file was encrypted
    pub encrypted_at: Option<std::time::SystemTime>,
}

// ============================================================================
// LISTING DOMAIN SERVICES
// ============================================================================

/// Options for directory listing operations
#[derive(Debug, Clone)]
pub struct ListingOptions {
    /// Whether to verify passwords for each file
    pub verify_passwords: bool,
    /// Whether to include subdirectories recursively
    pub recursive: bool,
    /// Whether to show detailed metadata
    pub show_details: bool,
    /// File pattern filter (glob-style)
    pub pattern_filter: Option<String>,
}

/// Information about a single encrypted file in a directory listing
#[derive(Debug, Clone)]
pub struct EncryptedFileInfo {
    /// Path to the encrypted file
    pub path: EncryptedFilePath,
    /// Original filename (None if password verification failed)
    pub original_filename: Option<String>,
    /// Algorithm used for encryption
    pub algorithm: AlgorithmId,
    /// File format version
    pub version: u16,
    /// File size in bytes
    pub size: u64,
    /// Last modified time
    pub modified: std::time::SystemTime,
    /// Whether the provided password can decrypt this file
    pub password_valid: bool,
    /// Content hash (if available and accessible)
    pub content_hash: Option<String>,
}

/// Result of a directory listing operation
#[derive(Debug, Clone)]
pub struct DirectoryListing {
    /// Directory that was scanned
    pub directory: std::path::PathBuf,
    /// List of encrypted files found
    pub files: Vec<EncryptedFileInfo>,
    /// Time taken for the scan operation
    pub scan_duration: Duration,
    /// Number of files that couldn't be processed
    pub failed_files: usize,
}

/// Core listing service abstraction
///
/// Represents the domain's need to list and inspect encrypted files.
/// This service works with file system paths and metadata, using FileHandler
/// for actual file access when needed.
pub trait ListingService: Send + Sync {
    /// Scan a directory for encrypted files and extract metadata
    /// 
    /// Uses FileHandler internally for file access but operates primarily
    /// on filesystem paths and cached metadata.
    fn scan_directory(
        &self,
        directory: &Path,
        password: Option<&str>,
        options: &ListingOptions,
    ) -> ServiceResult<DirectoryListing>;

    /// Get detailed information about a single encrypted file
    /// 
    /// May use FileHandler to read file headers and metadata but does not
    /// load full file content into memory.
    fn inspect_file(
        &self,
        file_path: &EncryptedFilePath,
        password: Option<&str>,
    ) -> ServiceResult<EncryptedFileInfo>;

    /// Find all encrypted files matching a pattern
    /// 
    /// Filesystem traversal operation that identifies encrypted files
    /// by extension and header validation.
    fn find_encrypted_files(
        &self,
        search_path: &Path,
        pattern: &str,
        recursive: bool,
    ) -> ServiceResult<Vec<EncryptedFilePath>>;
}

// ============================================================================
// FILE OPERATION WORKFLOWS  
// ============================================================================

/// High-level file operation workflows that combine multiple services
/// 
/// These traits represent complex domain operations that coordinate between
/// encryption/decryption services, file handler, and other domain services.
/// They handle the complete workflow including file I/O transactions.
pub trait FileOperationWorkflow: Send + Sync {
    /// Complete encryption workflow: read plaintext → encrypt → write encrypted
    /// 
    /// Coordinates between FileHandler (for I/O) and EncryptionService (for crypto).
    /// Handles atomic transactions to ensure consistency.
    fn encrypt_file_workflow(
        &self,
        source_path: &PlaintextFilePath,
        password: &str,
        options: &EncryptionOptions,
    ) -> ServiceResult<EncryptionResult>;

    /// Complete decryption workflow: read encrypted → decrypt → write plaintext
    /// 
    /// Coordinates between FileHandler (for I/O) and DecryptionService (for crypto).
    /// Handles atomic transactions to ensure consistency.
    fn decrypt_file_workflow(
        &self,
        source_path: &EncryptedFilePath,
        password: &str,
        options: &DecryptionOptions,
    ) -> ServiceResult<DecryptionResult>;

    /// Batch encryption with atomic transaction for all files
    fn encrypt_files_batch(
        &self,
        source_paths: &[&PlaintextFilePath],
        password: &str,
        options: &EncryptionOptions,
    ) -> ServiceResult<Vec<ServiceResult<EncryptionResult>>>;

    /// Batch decryption with atomic transaction for all files
    fn decrypt_files_batch(
        &self,
        source_paths: &[&EncryptedFilePath],
        password: &str,
        options: &DecryptionOptions,
    ) -> ServiceResult<Vec<ServiceResult<DecryptionResult>>>;
}

// ============================================================================
// MIGRATION AND ADVANCED OPERATIONS
// ============================================================================

/// Service for migration and advanced file operations
/// 
/// Handles operations that require multiple encryption/decryption cycles
/// or complex transformations between file formats.
pub trait MigrationService: Send + Sync {
    /// Re-encrypt files with a different algorithm or password
    /// 
    /// decrypt(old_password) → encrypt(new_password, new_algorithm)
    fn re_encrypt_file(
        &self,
        source_path: &EncryptedFilePath,
        old_password: &str,
        new_password: &str,
        new_algorithm: Option<AlgorithmId>,
    ) -> ServiceResult<EncryptionResult>;

    /// Migrate file to a different format version
    /// 
    /// decrypt → update_format → encrypt_with_new_format
    fn migrate_file_version(
        &self,
        source_path: &EncryptedFilePath,
        password: &str,
        target_version: u16,
    ) -> ServiceResult<EncryptedFile>;

    /// Verify integrity of encrypted files (read-only operation)
    fn verify_file_integrity(
        &self,
        file_path: &EncryptedFilePath,
        password: &str,
    ) -> ServiceResult<bool>;
}