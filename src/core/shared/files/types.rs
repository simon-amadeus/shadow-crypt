//! File-related types for the functional pipeline.

use std::path::PathBuf;
use std::time::SystemTime;
use crate::core::shared::crypto::{SecureBox};
use crate::core::shared::files::format::TlvHeader;
use crate::core::shared::files::ContentHash;

// ============================================================================
// FILE CLASSIFICATION
// ============================================================================

/// File type classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    EncryptedShadow,
    Other,
}

impl FileType {
    pub fn is_encryptable(&self) -> bool {
        matches!(self, FileType::Regular)
    }
    
    pub fn is_encrypted(&self) -> bool {
        matches!(self, FileType::EncryptedShadow)
    }
}

/// Tagged union for files in the pipeline.
#[derive(Debug, Clone)]
pub enum FileJob {
    /// Regular file that can be encrypted
    Plaintext {
        path: PathBuf,
        info: FileInfo,
        hash: ContentHash,
    },
    /// Encrypted Shadow file that can be decrypted
    Encrypted {
        path: PathBuf,
        info: FileInfo,
        header: TlvHeader,
    },
}

impl FileJob {
    pub fn path(&self) -> &PathBuf {
        match self {
            FileJob::Plaintext { path, .. } => path,
            FileJob::Encrypted { path, .. } => path,
        }
    }
    
    pub fn info(&self) -> &FileInfo {
        match self {
            FileJob::Plaintext { info, .. } => info,
            FileJob::Encrypted { info, .. } => info,
        }
    }
    
    pub fn is_plaintext(&self) -> bool {
        matches!(self, FileJob::Plaintext { .. })
    }
    
    pub fn is_encrypted(&self) -> bool {
        matches!(self, FileJob::Encrypted { .. })
    }
}

// ============================================================================
// FILE INFORMATION
// ============================================================================

/// Basic file system information.
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub filename: String,
    pub size: u64,
    pub modified: SystemTime,
    pub created: Option<SystemTime>,
    pub file_type: FileType,
}

impl FileInfo {
    pub fn new(
        filename: String,
        size: u64,
        modified: SystemTime,
        created: Option<SystemTime>,
        file_type: FileType,
    ) -> Self {
        Self {
            filename,
            size,
            modified,
            created,
            file_type,
        }
    }
}

// ============================================================================
// DATA CONTAINERS
// ============================================================================

/// Plaintext file data ready for encryption.
#[derive(Debug)]
pub struct PlaintextData {
    pub path: PathBuf,
    pub content: SecureBox<Vec<u8>>,
    pub hash: ContentHash,
    pub info: FileInfo,
}

impl PlaintextData {
    pub fn new(
        path: PathBuf,
        content: SecureBox<Vec<u8>>,
        hash: ContentHash,
        info: FileInfo,
    ) -> Self {
        Self {
            path,
            content,
            hash,
            info,
        }
    }
    
    pub fn size(&self) -> usize {
        self.content.expose_secret().len()
    }
}

/// Encrypted file data ready for writing.
#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub header: TlvHeader,
    pub ciphertext: Vec<u8>,
    pub plaintext_filename: Option<String>,
    pub obfuscated_filename: String,
}

impl EncryptedData {
    pub fn new(
        header: TlvHeader,
        ciphertext: Vec<u8>,
        plaintext_filename: Option<String>,
        obfuscated_filename: String,
    ) -> Self {
        Self {
            header,
            ciphertext,
            plaintext_filename,
            obfuscated_filename,
        }
    }
    
    pub fn total_size(&self) -> usize {
        self.header.serialized_size() + self.ciphertext.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.ciphertext.is_empty()
    }
}