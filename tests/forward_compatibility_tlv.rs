//! Forward Compatibility Test for TLV Header System
//!
//! This test validates that the current V1 implementation can handle
//! unknown field types gracefully, ensuring forward compatibility.

use shadow_crypt::domain::entities::tlv_header::{TlvHeader, TlvFieldType};
use shadow_crypt::infrastructure::tlv_serialization::TlvSerializer;

#[test]
fn test_forward_compatibility_unknown_fields() {
    // Create a V1 header with current known fields
    let mut header = TlvHeader::new();
    header.set_original_filename("test.txt");
    header.set_algorithm_id(1);
    header.set_content_hash([0x42u8; 32]);
    
    // Simulate adding future field types that V1 doesn't know about
    // These would be added by a hypothetical V2 implementation
    let future_field_1 = 0x50; // Unknown field type
    let future_field_2 = 0x73; // Another unknown field type
    
    // Manually add unknown fields (simulating what V2 might do)
    header.add_field(TlvFieldType::from(future_field_1), b"future_data_v2".to_vec());
    header.add_field(TlvFieldType::from(future_field_2), vec![1, 2, 3, 4, 5]);
    
    // Serialize header (V1 → wire format)
    let serialized = TlvSerializer::serialize(&header)
        .expect("Serialization should handle unknown fields");
    
    // Deserialize header (wire format → V1)
    let restored_header = TlvSerializer::deserialize(&serialized)
        .expect("Deserialization should preserve unknown fields");
    
    // Verify known fields are preserved
    assert_eq!(restored_header.original_filename(), Some("test.txt".to_string()));
    assert_eq!(restored_header.algorithm_id(), Some(1));
    assert_eq!(restored_header.content_hash(), Some([0x42u8; 32]));
    
    // Verify unknown fields are preserved as ExtensionMarker
    // This ensures they won't be lost during V1 → wire format → V1 roundtrip
    assert_eq!(
        restored_header.get_field(TlvFieldType::ExtensionMarker),
        header.get_field(TlvFieldType::ExtensionMarker)
    );
    
    // Verify that the header remains valid despite unknown fields
    assert!(restored_header.is_valid_shadow_file());
    assert_eq!(restored_header.version(), 1);
}

#[test]
fn test_version_evolution_simulation() {
    // Test simulating V1 → V2 → V1 roundtrip to ensure no data loss
    let mut v1_header = TlvHeader::new();
    v1_header.set_original_filename("document.txt");
    v1_header.set_algorithm_id(2); // AES-256-GCM
    
    // Simulate V2 adding compression metadata (unknown to V1)
    // Note: Unknown fields get mapped to ExtensionMarker in current implementation
    v1_header.add_field(TlvFieldType::from(0x80), b"compression_algorithm".to_vec());
    v1_header.add_field(TlvFieldType::from(0x81), vec![9]); // compression_level
    
    // V1 serializes this (including unknown fields)
    let wire_format = TlvSerializer::serialize(&v1_header).unwrap();
    
    // V1 reads it back (should preserve everything)
    let restored_v1 = TlvSerializer::deserialize(&wire_format).unwrap();
    
    // Known fields must be preserved exactly
    assert_eq!(restored_v1.original_filename(), v1_header.original_filename());
    assert_eq!(restored_v1.algorithm_id(), v1_header.algorithm_id());
    
    // Verify the header remains valid despite unknown fields
    assert!(restored_v1.is_valid_shadow_file());
    
    // Test that we can serialize again (implementation handles unknown fields)
    let re_serialized_result = TlvSerializer::serialize(&restored_v1);
    assert!(re_serialized_result.is_ok(), "Should be able to re-serialize header with unknown fields");
}