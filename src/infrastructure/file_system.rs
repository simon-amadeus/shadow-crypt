//! # File System Infrastructure
//!
//! File system operations and repository implementations.
//! 
//! NOTE: This implementation needs to be updated to match the new FileHandler 
//! trait interface located in domain::services::file_handler.

use crate::domain::entities::encrypted_file::EncryptedFileError;
use crate::domain::entities::header::TlvHeader;
// TODO: Update implementation to match new FileHandler trait
// use crate::domain::services::file_handler::{FileHandler, FileResult};
use crate::domain::entities::metadata::{FileMetadata, FileType};
use std::fs::{File, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// File system operations for encrypted files
pub struct FileSystemService;

impl FileSystemService {
    /// Read just the TLV header from an encrypted file without loading the entire content
    /// This enables efficient metadata extraction for duplicate detection
    pub fn read_header_only(path: &Path) -> Result<TlvHeader, EncryptedFileError> {
        use crate::domain::services::tlv_parser::TlvParser;
        
        let mut file = File::open(path)
            .map_err(|e| EncryptedFileError::IoError(format!("Failed to open file '{}': {}", path.display(), e)))?;
        
        // Use streaming parser for efficient header-only reading
        TlvSerializer::parse_header_from_reader(&mut file)
            .map_err(|e| EncryptedFileError::HeaderParseError(format!(
                "Failed to parse header from '{}': {}", 
                path.display(), 
                e
            )))
    }
    
    /// Extract content hash from an encrypted file's header
    /// This is the key operation needed for duplicate detection
    pub fn extract_content_hash(path: &Path) -> Result<Option<[u8; 32]>, EncryptedFileError> {
        let header = Self::read_header_only(path)?;
        Ok(header.content_hash())
    }
    
    /// Check if a file is a valid Shadow encrypted file
    pub fn is_shadow_file(path: &Path) -> bool {
        Self::read_header_only(path).is_ok()
    }
    
    /// Write an encrypted file to disk with atomic operation
    /// Ensures file integrity by writing to temporary file first, then renaming
    pub fn write_encrypted_file(
        path: &Path,
        header: &TlvHeader,
        ciphertext: &[u8]
    ) -> Result<(), EncryptedFileError> {
        use std::fs::{File, rename, remove_file};
        use std::io::Write;
        use std::path::PathBuf;
        
        // Create temporary file path with unique suffix to avoid conflicts
        let mut temp_path = PathBuf::from(path);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        temp_path.set_extension(format!("{}.tmp.{}", 
            path.extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("shadow"),
            timestamp
        ));
        
        // Serialize header first to catch any serialization errors early
        let header_bytes = TlvSerializer::serialize(header)
            .map_err(|e| EncryptedFileError::HeaderParseError(format!(
                "Failed to serialize header for '{}': {}", 
                path.display(), 
                e
            )))?;
        
        // Write to temporary file with error cleanup
        let write_result = {
            let mut temp_file = File::create(&temp_path)
                .map_err(|e| EncryptedFileError::IoError(format!(
                    "Failed to create temporary file '{}': {}", 
                    temp_path.display(), 
                    e
                )))?;
            
            // Write header
            temp_file.write_all(&header_bytes)
                .map_err(|e| EncryptedFileError::IoError(format!(
                    "Failed to write header to '{}': {}", 
                    temp_path.display(), 
                    e
                )))?;
            
            // Write ciphertext
            temp_file.write_all(ciphertext)
                .map_err(|e| EncryptedFileError::IoError(format!(
                    "Failed to write ciphertext to '{}': {}", 
                    temp_path.display(), 
                    e
                )))?;
            
            // Ensure data is written to disk before proceeding
            temp_file.sync_all()
                .map_err(|e| EncryptedFileError::IoError(format!(
                    "Failed to sync file '{}' to disk: {}", 
                    temp_path.display(), 
                    e
                )))
        };
        
        // If writing failed, clean up temporary file
        if let Err(ref write_error) = write_result {
            let _ = remove_file(&temp_path); // Best effort cleanup, ignore errors
            return Err(write_error.clone());
        }
        
        // Atomically rename temporary file to final destination
        rename(&temp_path, path)
            .map_err(|e| {
                let _ = remove_file(&temp_path); // Cleanup on rename failure
                EncryptedFileError::IoError(format!(
                    "Failed to move '{}' to final location '{}': {}", 
                    temp_path.display(), 
                    path.display(), 
                    e
                ))
            })?;
        
        Ok(())
    }
    
    /// Scan directory for Shadow encrypted files and extract metadata
    /// Returns list of paths with their content hashes for duplicate detection
    pub fn scan_directory_for_shadow_files(
        dir_path: &Path
    ) -> Result<Vec<(PathBuf, Option<[u8; 32]>)>, EncryptedFileError> {
        use std::fs;
        
        let mut shadow_files = Vec::new();
        
        // Read directory entries
        let entries = fs::read_dir(dir_path)
            .map_err(|e| EncryptedFileError::IoError(format!(
                "Failed to read directory '{}': {}", 
                dir_path.display(), 
                e
            )))?;
        
        for entry in entries {
            let entry = entry
                .map_err(|e| EncryptedFileError::IoError(format!(
                    "Failed to read directory entry in '{}': {}", 
                    dir_path.display(), 
                    e
                )))?;
            
            let path = entry.path();
            
            // Skip directories and focus only on files
            if path.is_dir() {
                continue;
            }
            
            // Check if it's a shadow file and extract content hash
            // Use optimized detection first (cheaper than full header parse)
            if Self::is_shadow_file(&path) {
                match Self::extract_content_hash(&path) {
                    Ok(content_hash) => {
                        shadow_files.push((path, content_hash));
                    }
                    Err(EncryptedFileError::HeaderParseError(_)) => {
                        // File looks like Shadow file but has corrupted header
                        // Include it in results without hash for potential recovery
                        shadow_files.push((path, None));
                    }
                    Err(e) => {
                        // Other errors (I/O, etc.) should be reported
                        return Err(e);
                    }
                }
            }
        }
        
        Ok(shadow_files)
    }
}

/// Standard file repository implementation using real filesystem
pub struct StandardFileRepository;

impl StandardFileRepository {
    /// Create new standard file repository
    pub fn new() -> Self {
        Self
    }
    
    /// Secure file deletion with content overwriting
    /// 
    /// This function attempts to prevent data recovery by:
    /// 1. Overwriting the file with cryptographically secure random data
    /// 2. Synchronizing to ensure data is written to disk
    /// 3. Removing the file from the filesystem
    /// 
    /// Note: Effectiveness depends on the underlying filesystem and storage medium.
    /// SSDs and modern filesystems may not guarantee secure deletion due to
    /// wear leveling and copy-on-write mechanisms.
    fn secure_delete_internal(path: &Path) -> CryptoResult<()> {
        use getrandom;
        
        // Ensure file exists before attempting deletion
        if !path.exists() {
            return Err(format!("File does not exist: {}", path.display()).into());
        }
        
        // Get file size to determine how much to overwrite
        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("Failed to get metadata for '{}': {}", path.display(), e))?;
        let file_size = metadata.len();
        
        if file_size == 0 {
            // Empty file, just remove it directly
            std::fs::remove_file(path)
                .map_err(|e| format!("Failed to remove empty file '{}': {}", path.display(), e))?;
            return Ok(());
        }
        
        // Open file for writing (preserving original size)
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(|e| format!("Failed to open file '{}' for secure deletion: {}", path.display(), e))?;
        
        // Seek to beginning
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("Failed to seek in file '{}': {}", path.display(), e))?;
        
        // Overwrite with random data in chunks
        const BUFFER_SIZE: usize = 8192; // 8KB buffer for efficiency
        let mut buffer = [0u8; BUFFER_SIZE];
        let mut remaining = file_size;
        
        while remaining > 0 {
            let chunk_size = std::cmp::min(remaining, BUFFER_SIZE as u64) as usize;
            
            // Fill buffer with random data
            getrandom::fill(&mut buffer[..chunk_size])
                .map_err(|e| format!("Failed to generate random data for secure deletion: {}", e))?;
            
            // Write random data to file
            file.write_all(&buffer[..chunk_size])
                .map_err(|e| format!("Failed to overwrite file '{}': {}", path.display(), e))?;
            
            remaining -= chunk_size as u64;
        }
        
        // Ensure data is written to disk
        file.sync_all()
            .map_err(|e| format!("Failed to sync file '{}': {}", path.display(), e))?;
        
        // Drop the file handle to close it
        drop(file);
        
        // Finally, remove the file from filesystem
        std::fs::remove_file(path)
            .map_err(|e| format!("Failed to remove file '{}': {}", path.display(), e))?;
        
        Ok(())
    }
}

impl Default for StandardFileRepository {
    fn default() -> Self {
        Self::new()
    }
}

// TODO: Update this implementation to match the new FileHandler trait in domain::services::file_handler
// The current implementation uses outdated method signatures and types.
/*
impl FileHandler for StandardFileRepository {
    fn read_file(&self, path: &Path) -> CryptoResult<Vec<u8>> {
        std::fs::read(path)
            .map_err(|e| {
                match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        format!("File not found: '{}'", path.display())
                    }
                    std::io::ErrorKind::PermissionDenied => {
                        format!("Permission denied reading file: '{}'", path.display())
                    }
                    _ => {
                        format!("Failed to read file '{}': {}", path.display(), e)
                    }
                }
            }.into())
    }
    
    fn write_file(&self, path: &Path, content: &[u8]) -> CryptoResult<()> {
        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| {
                    match e.kind() {
                        std::io::ErrorKind::PermissionDenied => {
                            format!("Permission denied creating directory: '{}'", parent.display())
                        }
                        _ => {
                            format!("Failed to create parent directories for '{}': {}", path.display(), e)
                        }
                    }
                })?;
        }
        
        std::fs::write(path, content)
            .map_err(|e| {
                match e.kind() {
                    std::io::ErrorKind::PermissionDenied => {
                        format!("Permission denied writing file: '{}'", path.display())
                    }
                    std::io::ErrorKind::NotFound => {
                        format!("Parent directory does not exist for: '{}'", path.display())
                    }
                    _ => {
                        format!("Failed to write file '{}': {}", path.display(), e)
                    }
                }
            }.into())
    }
    
    fn write_file_atomic(&self, path: &Path, content: &[u8]) -> CryptoResult<()> {
        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create parent directories for '{}': {}", path.display(), e))?;
        }
        
        // Create temporary file path
        let temp_path = path.with_extension("tmp");
        
        // Write to temporary file first
        {
            let mut temp_file = File::create(&temp_path)
                .map_err(|e| format!("Failed to create temp file '{}': {}", temp_path.display(), e))?;
            
            temp_file.write_all(content)
                .map_err(|e| format!("Failed to write to temp file '{}': {}", temp_path.display(), e))?;
            
            // Ensure data is written to disk before rename
            temp_file.sync_all()
                .map_err(|e| format!("Failed to sync temp file '{}': {}", temp_path.display(), e))?;
        }
        
        // Atomic rename
        std::fs::rename(&temp_path, path)
            .map_err(|e| {
                // Clean up temp file on failure
                let _ = std::fs::remove_file(&temp_path);
                format!("Failed to atomically move '{}' to '{}': {}", temp_path.display(), path.display(), e)
            })?;
        
        Ok(())
    }
    
    fn delete_file_secure(&self, path: &Path) -> CryptoResult<()> {
        Self::secure_delete_internal(path)
    }
    
    fn file_exists(&self, path: &Path) -> bool {
        path.exists()
    }
    
    fn file_metadata(&self, path: &Path) -> CryptoResult<FileMetadata> {
        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("Failed to get metadata for '{}': {}", path.display(), e))?;
        
        let file_type = if metadata.is_dir() {
            FileType::Directory
        } else if metadata.is_file() {
            FileType::Regular
        } else {
            // Check for symlinks on Unix systems
            #[cfg(unix)]
            {
                if metadata.file_type().is_symlink() {
                    FileType::Symlink
                } else {
                    FileType::Other
                }
            }
            #[cfg(not(unix))]
            {
                FileType::Other
            }
        };
        
        let original_filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        
        let modified_time = metadata.modified()
            .unwrap_or(SystemTime::UNIX_EPOCH);
        
        let created_time = metadata.created().ok();
        
        Ok(FileMetadata {
            original_filename,
            file_size: metadata.len(),
            modified_time,
            created_time,
            file_type,
        })
    }
}
*/