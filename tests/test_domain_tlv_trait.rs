//! Test the domain TLV parser trait implementation

use shadow_crypt::domain::entities::tlv_header::TlvHeader;
use shadow_crypt::domain::services::tlv_parser::TlvParser;
use shadow_crypt::infrastructure::tlv_serialization::TlvSerializer;

#[test]
fn test_domain_trait_basic_roundtrip() {
    // Test that the domain trait works for basic operations
    let mut header = TlvHeader::new();
    header.set_original_filename("test.txt");
    header.set_algorithm_id(1);
    
    // Serialize using domain trait
    let serialized = TlvSerializer::serialize_header(&header).unwrap();
    
    // Deserialize using domain trait
    let (parsed_header, remaining) = TlvSerializer::parse_header_with_remainder(&serialized).unwrap();
    
    // Verify
    assert_eq!(parsed_header.original_filename(), header.original_filename());
    assert_eq!(parsed_header.algorithm_id(), header.algorithm_id());
    assert!(remaining.is_empty());
}

#[test]
fn test_domain_trait_with_ciphertext() {
    // Test boundary detection through domain trait
    let header = TlvHeader::new();
    let mut file_data = TlvSerializer::serialize_header(&header).unwrap();
    file_data.extend_from_slice(b"ciphertext");
    
    let (parsed_header, remaining) = TlvSerializer::parse_header_with_remainder(&file_data).unwrap();
    
    assert_eq!(parsed_header.version(), header.version());
    assert_eq!(remaining, b"ciphertext");
}

#[test]
fn test_domain_validation_rules() {
    // Test that domain validation is enforced
    assert!(!TlvSerializer::is_valid_field_type(0x00)); // Null byte should be invalid
    assert!(TlvSerializer::is_valid_field_type(0x01));  // Standard type should be valid
    assert!(TlvSerializer::is_valid_field_type(0x50));  // Future type should be valid
    assert!(TlvSerializer::is_valid_field_type(0xFF));  // Extension marker should be valid
    
    assert_eq!(TlvSerializer::max_field_length(), 65536);
}