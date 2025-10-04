//! Integration tests for EncryptedFile I/O operations
//!
//! Tests the complete workflow of reading and writing encrypted files
//! with TLV header integration and content hash extraction.

use shadow_crypt::domain::entities::encrypted_file::{EncryptedFile, EncryptedFileError};
use shadow_crypt::domain::entities::tlv_header::TlvHeader;
use shadow_crypt::infrastructure::file_system::FileSystemService;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_encrypted_file_write_and_read_roundtrip() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let test_file_path = temp_dir.path().join("test.shadow");
    
    // Create test data
    let mut header = TlvHeader::new();
    header.set_original_filename("test.txt");
    header.set_content_hash([0x42u8; 32]);
    header.set_algorithm_id(1);
    
    let ciphertext = b"encrypted test content".to_vec();
    let encrypted_file = EncryptedFile::new(header, ciphertext.clone());
    
    // Write file
    encrypted_file.write_to_file(&test_file_path)
        .expect("Failed to write encrypted file");
    
    // Verify file exists
    assert!(test_file_path.exists());
    
    // Read file back
    let loaded_file = EncryptedFile::from_file(&test_file_path, "dummy_password")
        .expect("Failed to read encrypted file");
    
    // Verify data integrity
    assert_eq!(loaded_file.ciphertext(), ciphertext.as_slice());
    assert_eq!(loaded_file.original_filename(), Some("test.txt"));
    assert_eq!(loaded_file.content_hash(), Some([0x42u8; 32]));
    assert_eq!(loaded_file.version(), 1);
}

#[test]
fn test_file_system_service_header_only_reading() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let test_file_path = temp_dir.path().join("test.shadow");
    
    // Create and write test file
    let mut header = TlvHeader::new();
    header.set_original_filename("metadata_test.txt");
    
    let test_hash: [u8; 32] = {
        let pattern = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let mut hash = [0u8; 32];
        for (i, &byte) in pattern.iter().cycle().take(32).enumerate() {
            hash[i] = byte;
        }
        hash
    };
    header.set_content_hash(test_hash);
    
    let large_ciphertext = vec![0xFFu8; 1024]; // 1KB of data instead of 1MB
    
    FileSystemService::write_encrypted_file(&test_file_path, &header, &large_ciphertext)
        .expect("Failed to write test file");
    
    // Read just the header
    let read_header = FileSystemService::read_header_only(&test_file_path)
        .expect("Failed to read header");
    
    // Verify header data without loading large ciphertext
    assert_eq!(read_header.original_filename(), Some("metadata_test.txt".to_string()));
    assert_eq!(read_header.content_hash(), Some(test_hash));
}

#[test]
fn test_content_hash_extraction() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let test_file_path = temp_dir.path().join("hash_test.shadow");
    
    // Create test file with specific content hash
    let test_hash = [0xABu8; 32];
    let mut header = TlvHeader::new();
    header.set_content_hash(test_hash);
    
    FileSystemService::write_encrypted_file(&test_file_path, &header, b"test content")
        .expect("Failed to write test file");
    
    // Extract content hash directly
    let extracted_hash = FileSystemService::extract_content_hash(&test_file_path)
        .expect("Failed to extract content hash");
    
    assert_eq!(extracted_hash, Some(test_hash));
}

#[test]
fn test_directory_scanning() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    
    // Create multiple shadow files with different content hashes
    let files = [
        ("file1.shadow", [0x11u8; 32]),
        ("file2.shadow", [0x22u8; 32]),
        ("file3.shadow", [0x33u8; 32]),
    ];
    
    for (filename, hash) in &files {
        let file_path = temp_dir.path().join(filename);
        let mut header = TlvHeader::new();
        header.set_content_hash(*hash);
        
        FileSystemService::write_encrypted_file(&file_path, &header, b"test content")
            .expect("Failed to write test file");
    }
    
    // Create a non-shadow file to test filtering
    let non_shadow_path = temp_dir.path().join("regular.txt");
    fs::write(&non_shadow_path, "regular content").expect("Failed to write regular file");
    
    // Scan directory
    let shadow_files = FileSystemService::scan_directory_for_shadow_files(temp_dir.path())
        .expect("Failed to scan directory");
    
    // Verify results
    assert_eq!(shadow_files.len(), 3);
    
    // Check that all hashes are present
    let found_hashes: Vec<_> = shadow_files.iter()
        .filter_map(|(_, hash)| *hash)
        .collect();
    
    assert!(found_hashes.contains(&[0x11u8; 32]));
    assert!(found_hashes.contains(&[0x22u8; 32]));
    assert!(found_hashes.contains(&[0x33u8; 32]));
}

#[test]
fn test_shadow_file_detection() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    
    // Create a valid shadow file
    let shadow_path = temp_dir.path().join("valid.shadow");
    let header = TlvHeader::new();
    FileSystemService::write_encrypted_file(&shadow_path, &header, b"test")
        .expect("Failed to write shadow file");
    
    // Create an invalid file
    let invalid_path = temp_dir.path().join("invalid.txt");
    fs::write(&invalid_path, "not a shadow file").expect("Failed to write invalid file");
    
    // Test detection
    assert!(FileSystemService::is_shadow_file(&shadow_path));
    assert!(!FileSystemService::is_shadow_file(&invalid_path));
    assert!(!FileSystemService::is_shadow_file(&PathBuf::from("nonexistent.shadow")));
}

#[test]
fn test_error_handling() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    
    // Test reading nonexistent file
    let nonexistent_path = temp_dir.path().join("nonexistent.shadow");
    let result = EncryptedFile::from_file(&nonexistent_path, "password");
    assert!(matches!(result, Err(EncryptedFileError::IoError(_))));
    
    // Test reading invalid shadow file
    let invalid_path = temp_dir.path().join("invalid.shadow");
    fs::write(&invalid_path, "invalid content").expect("Failed to write invalid file");
    
    let result = FileSystemService::read_header_only(&invalid_path);
    assert!(matches!(result, Err(EncryptedFileError::HeaderParseError(_))));
}

#[test]
fn test_atomic_write_operation() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let target_path = temp_dir.path().join("atomic_test.shadow");
    
    // Create test data
    let header = TlvHeader::new();
    let content = b"atomic write test".to_vec();
    
    // Write file
    FileSystemService::write_encrypted_file(&target_path, &header, &content)
        .expect("Failed to write file atomically");
    
    // Verify final file exists and temporary file is cleaned up
    assert!(target_path.exists());
    
    // Check that no temporary files remain
    let temp_files: Vec<_> = fs::read_dir(temp_dir.path())
        .expect("Failed to read directory")
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.file_name().to_string_lossy().contains(".tmp")
        })
        .collect();
    
    assert!(temp_files.is_empty(), "Temporary files should be cleaned up");
}