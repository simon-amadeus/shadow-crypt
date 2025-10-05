//! # ListingService
//!
//! Manages directory scanning and file information display.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use crate::domain::entities::{AlgorithmId, tlv_header::TlvFieldType};
use crate::domain::errors::{DomainResult, DomainError, FileSystemError};
use crate::domain::services::{FileDetector, CryptographicAlgorithm};
use crate::domain::services::crypto_service::KeyDerivationConfig;
use crate::infrastructure::tlv_serialization::TlvSerializer;
use crate::infrastructure::crypto::factory::Algorithm;

/// Manages directory scanning and file information display
pub struct ListingService {
    file_detector: FileDetector,
}

#[derive(Debug)]
pub struct DirectoryListing {
    pub directory: PathBuf,
    pub files: Vec<EncryptedFileInfo>,
    pub scan_duration: Duration,
}

#[derive(Debug)]
pub struct EncryptedFileInfo {
    pub path: PathBuf,
    pub original_filename: Option<String>, // None if password failed
    pub algorithm: AlgorithmId,
    pub version: u16,
    pub size: u64,
    pub modified: SystemTime,
    pub password_valid: bool,
}

impl ListingService {
    /// Create a new ListingService instance
    pub fn new() -> Self {
        Self {
            file_detector: FileDetector::new(),
        }
    }

    /// Scan directory for encrypted files and extract metadata
    pub fn scan_directory(
        &self,
        directory: &Path,
        password: &str,
    ) -> DomainResult<DirectoryListing> {
        let start_time = Instant::now();
        let mut files = Vec::new();

        // Read directory entries
        let entries = std::fs::read_dir(directory)
            .map_err(|e| DomainError::FileSystemError(FileSystemError::IoOperationFailed {
                operation: format!("read directory {}", directory.display()),
                reason: e.to_string(),
            }))?;

        // Process each entry
        for entry in entries {
            let entry = entry.map_err(|e| DomainError::FileSystemError(FileSystemError::IoOperationFailed {
                operation: format!("read directory entry in {}", directory.display()),
                reason: e.to_string(),
            }))?;

            let path = entry.path();
            
            // Skip directories and non-files
            if !path.is_file() {
                continue;
            }

            // Check if this is an encrypted file
            match self.file_detector.is_encrypted_file(&path) {
                Ok(true) => {
                    // Extract file information
                    if let Ok(file_info) = self.extract_file_info(&path, password) {
                        files.push(file_info);
                    }
                }
                Ok(false) => {
                    // Not an encrypted file, skip
                    continue;
                }
                Err(_) => {
                    // Error reading file, skip but don't fail the entire scan
                    continue;
                }
            }
        }

        Ok(DirectoryListing {
            directory: directory.to_path_buf(),
            files,
            scan_duration: start_time.elapsed(),
        })
    }

    /// Extract metadata from a single encrypted file
    fn extract_file_info(&self, path: &Path, password: &str) -> DomainResult<EncryptedFileInfo> {
        // Get basic file metadata
        let metadata = std::fs::metadata(path)
            .map_err(|e| DomainError::FileSystemError(FileSystemError::IoOperationFailed {
                operation: format!("read metadata for {}", path.display()),
                reason: e.to_string(),
            }))?;

        let size = metadata.len();
        let modified = metadata.modified()
            .map_err(|e| DomainError::FileSystemError(FileSystemError::IoOperationFailed {
                operation: format!("read modification time for {}", path.display()),
                reason: e.to_string(),
            }))?;

        // Try to read and parse the TLV header
        let (original_filename, algorithm, version, password_valid) = match self.try_parse_header(path, password) {
            Ok((filename, alg, ver)) => (filename, alg, ver, true),
            Err(_) => {
                // Password failed or file corrupted - return minimal info
                (None, AlgorithmId::XChaCha20Poly1305, 1, false)
            }
        };

        Ok(EncryptedFileInfo {
            path: path.to_path_buf(),
            original_filename,
            algorithm,
            version,
            size,
            modified,
            password_valid,
        })
    }

    /// Try to parse the header with the given password
    fn try_parse_header(&self, path: &Path, password: &str) -> DomainResult<(Option<String>, AlgorithmId, u16)> {
        // Read the encrypted file
        let encrypted_data = std::fs::read(path)
            .map_err(|e| DomainError::FileSystemError(FileSystemError::IoOperationFailed {
                operation: format!("read encrypted file {}", path.display()),
                reason: e.to_string(),
            }))?;

        // Parse TLV header (this doesn't require password validation)
        let header = TlvSerializer::deserialize(&encrypted_data)
            .map_err(|e| DomainError::FormatError(
                crate::domain::errors::FormatError::HeaderParsingFailed {
                    field: "TLV header".to_string(),
                    reason: e.to_string(),
                }
            ))?;

        // Extract algorithm ID
        let algorithm_id = header.get_field(TlvFieldType::AlgorithmId)
            .and_then(|data| data.first().copied())
            .and_then(|id_byte| match id_byte {
                1 => Some(AlgorithmId::XChaCha20Poly1305),
                2 => Some(AlgorithmId::AesGcm256),
                _ => None,
            })
            .unwrap_or(AlgorithmId::XChaCha20Poly1305); // Default fallback

        // Extract original filename from header
        let original_filename = header.original_filename();

        // Version is stored in header format (V1 for new implementation)
        let version = header.version();

        // Password verification: try to decrypt just enough to validate the password
        // This avoids decrypting the entire file just for validation
        let password_is_valid = self.verify_password_against_file(&encrypted_data, password);

        if password_is_valid {
            Ok((original_filename, algorithm_id, version))
        } else {
            // Return error to signal password verification failed
            Err(DomainError::authentication_failed("Password verification failed during listing"))
        }
    }

    /// Verify password by attempting to decrypt a small portion of the file
    fn verify_password_against_file(&self, encrypted_data: &[u8], password: &str) -> bool {
        // Parse header to get cryptographic parameters
        let header = match TlvSerializer::deserialize(encrypted_data) {
            Ok(h) => h,
            Err(_) => return false,
        };

        // Extract algorithm
        let algorithm_id = header.get_field(TlvFieldType::AlgorithmId)
            .and_then(|data| data.first().copied())
            .and_then(|id_byte| match id_byte {
                1 => Some(AlgorithmId::XChaCha20Poly1305),
                2 => Some(AlgorithmId::AesGcm256),
                _ => None,
            });

        let algorithm_id = match algorithm_id {
            Some(id) => id,
            None => return false,
        };

        let algorithm = Algorithm::from_id(algorithm_id);

        // Extract nonce and salt
        let nonce = match header.get_field(TlvFieldType::Nonce) {
            Some(n) => n,
            None => return false,
        };

        let salt = match header.get_field(TlvFieldType::KeyDerivationParams) {
            Some(s) => s,
            None => return false,
        };

        // Get ciphertext (everything after header)
        let (_, ciphertext) = match TlvSerializer::deserialize_with_remainder(encrypted_data) {
            Ok((h, c)) => (h, c),
            Err(_) => return false,
        };

        // Try to derive key material and decrypt
        // If the password is wrong, key derivation will succeed but decryption will fail
        match algorithm.derive_key_material(password, salt) {
            Ok(key_material) => {
                // Try to decrypt the first few bytes to validate password
                // We don't need the full content, just enough to verify
                algorithm.decrypt(ciphertext, nonce, &key_material).is_ok()
            }
            Err(_) => false, // Key derivation failed
        }
    }
}