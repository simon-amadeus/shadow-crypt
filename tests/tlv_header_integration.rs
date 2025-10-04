//! Integration tests for TLV Header System V1
//!
//! These tests validate the complete TLV header flow from domain entities
//! through infrastructure serialization, demonstrating usage in encryption context.

use shadow_crypt::domain::entities::tlv_header::{TlvHeader, TlvFieldType};
use shadow_crypt::infrastructure::tlv_serialization::TlvSerializer;
use std::io::Write;

#[test]
fn test_encryption_header_workflow() {
    // Simulate creating a header for file encryption
    let mut header = TlvHeader::new();
    
    // Set metadata as would happen during encryption
    header.set_original_filename("important_document.pdf");
    header.set_content_hash([0x12u8; 32]); // Simulated SHA-256 hash
    header.set_algorithm_id(1); // XChaCha20-Poly1305
    header.set_nonce(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]); // 24-byte nonce for XChaCha20
    
    // Add custom directory path
    header.add_field(TlvFieldType::DirectoryPath, b"/home/user/documents".to_vec());
    
    // Serialize header (as would happen when writing encrypted file)
    let serialized_header = TlvSerializer::serialize(&header)
        .expect("Header serialization should succeed");
    
    // Verify header has expected structure
    assert!(serialized_header.len() > 10, "Serialized header should have substantial size");
    assert_eq!(&serialized_header[0..8], &TlvHeader::MAGIC_NUMBER, "Magic number should be at start");
    
    // Simulate reading the header back (as would happen during decryption)
    let restored_header = TlvSerializer::deserialize(&serialized_header)
        .expect("Header deserialization should succeed");
    
    // Verify all metadata is preserved
    assert!(restored_header.is_valid_shadow_file(), "Header should be valid Shadow file");
    assert_eq!(restored_header.version(), 1, "Should be version 1");
    assert_eq!(restored_header.original_filename(), Some("important_document.pdf".to_string()));
    assert_eq!(restored_header.content_hash(), Some([0x12u8; 32]));
    
    // Verify algorithm and nonce for decryption
    assert_eq!(restored_header.get_field(TlvFieldType::AlgorithmId), Some(&vec![1]));
    assert_eq!(restored_header.get_field(TlvFieldType::Nonce).unwrap().len(), 24);
    
    // Verify additional metadata
    assert_eq!(
        restored_header.get_field(TlvFieldType::DirectoryPath),
        Some(&b"/home/user/documents".to_vec())
    );
}

#[test]
fn test_minimal_encryption_header() {
    // Test minimal required fields for encryption
    let mut header = TlvHeader::new();
    header.set_algorithm_id(2); // AES-256-GCM
    header.set_nonce(vec![0xFF; 12]); // 12-byte nonce for AES-GCM
    
    let serialized = TlvSerializer::serialize(&header).unwrap();
    let restored = TlvSerializer::deserialize(&serialized).unwrap();
    
    assert!(restored.is_valid_shadow_file());
    assert_eq!(restored.get_field(TlvFieldType::AlgorithmId), Some(&vec![2]));
    assert_eq!(restored.get_field(TlvFieldType::Nonce), Some(&vec![0xFF; 12]));
    assert_eq!(restored.original_filename(), None); // No filename preserved
}

#[test]
fn test_duplicate_detection_workflow() {
    // Test content hash functionality for duplicate detection
    // Test data for potential future use
    let _content1 = b"This is some file content";
    let _content2 = b"This is different content";
    
    // Simulate computing SHA-256 hashes (would use actual SHA-256 in real implementation)
    let hash1 = [0x11u8; 32]; // Simulated hash of content1
    let hash2 = [0x22u8; 32]; // Simulated hash of content2
    
    let mut header1 = TlvHeader::new();
    header1.set_original_filename("file1.txt");
    header1.set_content_hash(hash1);
    
    let mut header2 = TlvHeader::new();
    header2.set_original_filename("file2.txt");
    header2.set_content_hash(hash2);
    
    // Serialize both headers
    let serialized1 = TlvSerializer::serialize(&header1).unwrap();
    let serialized2 = TlvSerializer::serialize(&header2).unwrap();
    
    // Deserialize and verify different hashes
    let restored1 = TlvSerializer::deserialize(&serialized1).unwrap();
    let restored2 = TlvSerializer::deserialize(&serialized2).unwrap();
    
    assert_ne!(restored1.content_hash(), restored2.content_hash());
    assert_eq!(restored1.content_hash(), Some(hash1));
    assert_eq!(restored2.content_hash(), Some(hash2));
}

#[test]
fn test_version_compatibility_detection() {
    // Test that we can detect file version for compatibility checking
    let header = TlvHeader::new();
    let serialized = TlvSerializer::serialize(&header).unwrap();
    
    // Manually verify the version bytes in the serialized data
    let version_bytes = &serialized[8..10]; // After 8-byte magic number
    let version = u16::from_le_bytes([version_bytes[0], version_bytes[1]]);
    assert_eq!(version, 1, "Version should be encoded as 1");
    
    let restored = TlvSerializer::deserialize(&serialized).unwrap();
    assert_eq!(restored.version(), 1);
}

#[test]
fn test_extensibility_future_fields() {
    // Test that unknown fields are preserved (future compatibility)
    let mut raw_data = Vec::new();
    
    // Write magic number and version
    raw_data.write_all(&TlvHeader::MAGIC_NUMBER).unwrap();
    raw_data.write_all(&1u16.to_le_bytes()).unwrap();
    
    // Write a future field type (0x50) that doesn't exist yet
    raw_data.write_all(&[0x50]).unwrap(); // Unknown field type
    raw_data.write_all(&4u32.to_le_bytes()).unwrap(); // Length: 4
    raw_data.write_all(b"data").unwrap(); // Value: "data"
    
    // Write a known field
    raw_data.write_all(&[TlvFieldType::OriginalFilename as u8]).unwrap();
    raw_data.write_all(&8u32.to_le_bytes()).unwrap();
    raw_data.write_all(b"test.txt").unwrap();
    
    // Deserialize should succeed and preserve unknown field
    let header = TlvSerializer::deserialize(&raw_data).unwrap();
    
    assert!(header.is_valid_shadow_file());
    assert_eq!(header.original_filename(), Some("test.txt".to_string()));
    
    // Unknown field should be mapped to ExtensionMarker
    assert_eq!(
        header.get_field(TlvFieldType::ExtensionMarker),
        Some(&b"data".to_vec())
    );
}

#[test]
fn test_large_file_metadata() {
    // Test handling of larger metadata (long filenames, paths)
    let long_filename = "a".repeat(255); // Maximum typical filename length
    let long_path = format!("/very/long/path/with/many/nested/directories/{}", "b".repeat(100));
    
    let mut header = TlvHeader::new();
    header.set_original_filename(&long_filename);
    header.add_field(TlvFieldType::DirectoryPath, long_path.as_bytes().to_vec());
    header.set_content_hash([0xABu8; 32]);
    
    let serialized = TlvSerializer::serialize(&header).unwrap();
    let restored = TlvSerializer::deserialize(&serialized).unwrap();
    
    assert_eq!(restored.original_filename(), Some(long_filename));
    assert_eq!(
        restored.get_field(TlvFieldType::DirectoryPath),
        Some(&long_path.as_bytes().to_vec())
    );
    assert_eq!(restored.content_hash(), Some([0xABu8; 32]));
}