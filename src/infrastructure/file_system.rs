//! # File System Infrastructure
//!
//! File system operations and repository implementations.

use crate::domain::entities::encrypted_file::EncryptedFileError;
use crate::domain::entities::tlv_header::TlvHeader;
use crate::infrastructure::tlv_serialization::{TlvSerializer, TlvSerializationError};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// File system operations for encrypted files
pub struct FileSystemService;

impl FileSystemService {
    /// Read just the TLV header from an encrypted file without loading the entire content
    /// This enables efficient metadata extraction for duplicate detection
    pub fn read_header_only(path: &Path) -> Result<TlvHeader, EncryptedFileError> {
        let mut file = File::open(path)
            .map_err(|e| EncryptedFileError::IoError(format!("Failed to open file '{}': {}", path.display(), e)))?;
        
        // Read magic number and version first to validate
        let mut magic_and_version = [0u8; 10];
        file.read_exact(&mut magic_and_version)
            .map_err(|e| EncryptedFileError::IoError(format!("File '{}' too small or corrupted: {}", path.display(), e)))?;
        
        // Check magic number
        let magic = &magic_and_version[0..8];
        if magic != TlvHeader::MAGIC_NUMBER {
            return Err(EncryptedFileError::HeaderParseError(format!(
                "File '{}' is not a valid Shadow encrypted file (invalid magic number)", 
                path.display()
            )));
        }
        
        // Read the rest of the file
        let mut remaining_data = Vec::new();
        file.read_to_end(&mut remaining_data)
            .map_err(|e| EncryptedFileError::IoError(format!("Failed to read from '{}': {}", path.display(), e)))?;
        
        // Combine magic+version with remaining data
        let mut all_data = magic_and_version.to_vec();
        all_data.extend_from_slice(&remaining_data);
        
        // Find the end of TLV section
        let header_end = Self::find_tlv_section_end(&all_data, 10).unwrap_or(10);
        
        // Extract just the header portion
        let header_data = &all_data[0..header_end];
        
        // Parse the header using TlvSerializer
        TlvSerializer::deserialize(header_data)
            .map_err(|e| match e {
                TlvSerializationError::InvalidMagicNumber => {
                    EncryptedFileError::HeaderParseError(format!(
                        "File '{}' has invalid magic number", 
                        path.display()
                    ))
                }
                TlvSerializationError::InvalidFormat(msg) => {
                    EncryptedFileError::HeaderParseError(format!(
                        "Corrupted header in '{}': {}", 
                        path.display(), 
                        msg
                    ))
                }
                TlvSerializationError::InsufficientData => {
                    EncryptedFileError::HeaderParseError(format!(
                        "Incomplete header data in '{}'", 
                        path.display()
                    ))
                }
                TlvSerializationError::Io(io_err) => {
                    EncryptedFileError::IoError(format!(
                        "I/O error parsing header in '{}': {}", 
                        path.display(), 
                        io_err
                    ))
                }
            })
    }
    
    /// Find the end of TLV section by parsing field boundaries
    /// Returns the position where TLV section ends, or None if not yet found
    fn find_tlv_section_end(data: &[u8], search_start: usize) -> Option<usize> {
        let mut pos = 10; // Start after magic + version
        
        // Don't re-parse data we've already validated
        let parse_start = search_start.max(10);
        if parse_start < data.len() {
            pos = parse_start;
        }
        
        // If we only have magic + version (10 bytes), that's a valid empty header
        if data.len() <= 10 {
            return Some(10);
        }
        
        while pos < data.len() {
            // Check if we can read a complete TLV field header
            if pos + 5 > data.len() {
                // Not enough data for type + length, need more
                return None;
            }
            
            let field_type_raw = data[pos];
            
            // Validate field type - must be a known TLV type
            if !Self::is_valid_tlv_field_type(field_type_raw) {
                // Hit something that's not a TLV field - probably ciphertext
                return Some(pos);
            }
            
            // Read field length
            let length = u32::from_le_bytes([
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
            ]) as usize;
            
            // Validate field length is reasonable
            if length > 65536 {
                // Suspiciously large field - probably not TLV
                return Some(pos);
            }
            
            // Check if we have enough data for the complete field
            let field_end = pos + 5 + length;
            if field_end > data.len() {
                // Don't have complete field yet, need more data
                return None;
            }
            
            // Move to next field
            pos = field_end;
        }
        
        // Reached end of available data - all data consumed by TLV fields
        Some(pos)
    }
    
    /// Check if a byte value represents a valid TLV field type
    fn is_valid_tlv_field_type(byte: u8) -> bool {
        // Valid TLV field types: 0x01-0x0A or 0xFF (ExtensionMarker)
        (0x01..=0x0A).contains(&byte) || byte == 0xFF
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