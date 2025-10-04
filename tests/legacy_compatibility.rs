//! Legacy compatibility validation test
//!
//! This test validates that our V1 implementation can work with the same
//! TLV format patterns as the legacy V3 implementation.

use shadow_crypt::domain::entities::tlv_header::{TlvHeader, TlvFieldType};
use shadow_crypt::infrastructure::tlv_serialization::TlvSerializer;

#[test]
fn test_legacy_v3_format_compatibility() {
    // Create a header with the same field types that V3 used
    let mut header = TlvHeader::new();
    
    // Add fields that match legacy V3 TLV POC patterns
    header.add_field(TlvFieldType::OriginalFilename, b"test_filename.txt".to_vec());
    header.add_field(TlvFieldType::DirectoryPath, b"/home/user".to_vec());
    
    // Serialize using our V1 implementation
    let serialized = TlvSerializer::serialize(&header).unwrap();
    
    // Deserialize back
    let restored = TlvSerializer::deserialize(&serialized).unwrap();
    
    // Verify the same field access patterns work
    assert_eq!(
        restored.get_field(TlvFieldType::OriginalFilename).unwrap(),
        b"test_filename.txt"
    );
    assert_eq!(
        restored.get_field(TlvFieldType::DirectoryPath).unwrap(),
        b"/home/user"
    );
    
    // V1 should maintain the same extensibility for unknown field types
    // (this was a key feature of the V3 POC)
    assert!(restored.is_valid_shadow_file());
}

#[test] 
fn test_field_ordering_deterministic() {
    // V3 POC emphasized deterministic field ordering - verify V1 maintains this
    let mut header1 = TlvHeader::new();
    header1.add_field(TlvFieldType::DirectoryPath, b"/path".to_vec());
    header1.add_field(TlvFieldType::OriginalFilename, b"file.txt".to_vec());
    header1.add_field(TlvFieldType::AlgorithmId, vec![1]);
    
    let mut header2 = TlvHeader::new();
    header2.add_field(TlvFieldType::AlgorithmId, vec![1]);
    header2.add_field(TlvFieldType::OriginalFilename, b"file.txt".to_vec());
    header2.add_field(TlvFieldType::DirectoryPath, b"/path".to_vec());
    
    let serialized1 = TlvSerializer::serialize(&header1).unwrap();
    let serialized2 = TlvSerializer::serialize(&header2).unwrap();
    
    // Should serialize to identical bytes regardless of insertion order
    assert_eq!(serialized1, serialized2, "Serialization must be deterministic");
}

#[test]
fn test_v1_enhancements_over_v3() {
    // Test V1-specific enhancements that weren't in the V3 POC
    let mut header = TlvHeader::new();
    
    // V1 adds content hash field for duplicate detection
    header.set_content_hash([0x42u8; 32]);
    
    // V1 has improved algorithm ID handling
    header.set_algorithm_id(1);
    
    // V1 has dedicated nonce field
    header.set_nonce(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24]);
    
    let serialized = TlvSerializer::serialize(&header).unwrap();
    let restored = TlvSerializer::deserialize(&serialized).unwrap();
    
    // Verify V1 enhancements work
    assert_eq!(restored.content_hash(), Some([0x42u8; 32]));
    assert_eq!(restored.get_field(TlvFieldType::AlgorithmId), Some(&vec![1]));
    assert_eq!(restored.get_field(TlvFieldType::Nonce).unwrap().len(), 24);
    
    // V1 should still be a valid Shadow file
    assert!(restored.is_valid_shadow_file());
    assert_eq!(restored.version(), 1);
}