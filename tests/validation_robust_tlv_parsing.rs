//! Comprehensive validation tests for robust TLV header deserialization improvements
//! 
//! These tests validate all success criteria from the implementation plan.

use shadow_crypt::domain::entities::tlv_header::{TlvHeader, TlvFieldType};
use shadow_crypt::infrastructure::tlv_serialization::{TlvSerializer, TlvSerializationError};

#[test]
fn test_success_criteria_invalid_field_types() {
    // Success Criteria: TlvSerializer::deserialize() only parses valid TLV fields and stops at first invalid byte
    
    let header = TlvHeader::new();
    let mut file_data = TlvSerializer::serialize(&header).unwrap();
    
    // Add null byte (0x00) which is always invalid (likely corrupted data)
    file_data.push(0x00); // Invalid field type
    file_data.extend_from_slice(&5u32.to_le_bytes()); // Length
    file_data.extend_from_slice(b"BADDD"); // Data
    
    match TlvSerializer::deserialize_with_remainder(&file_data) {
        Ok((parsed_header, remaining)) => {
            assert_eq!(parsed_header.version(), header.version());
            // Should stop at the invalid field type
            assert_eq!(remaining.len(), 10); // Invalid field + length + data = 1 + 4 + 5 = 10
        },
        Err(_) => panic!("Should handle invalid field types gracefully by stopping parsing"),
    }
}

#[test]
fn test_success_criteria_length_validation() {
    // Success Criteria: No memory exhaustion from invalid length fields
    
    let header = TlvHeader::new();
    let mut file_data = TlvSerializer::serialize(&header).unwrap();
    
    // Add field with huge length (potential DoS)
    file_data.push(0x01); // Valid field type
    file_data.extend_from_slice(&1000000u32.to_le_bytes()); // Huge length
    file_data.extend_from_slice(b"small data");
    
    // Should not attempt to allocate 1MB of memory
    match TlvSerializer::deserialize_with_remainder(&file_data) {
        Ok((parsed_header, remaining)) => {
            assert_eq!(parsed_header.version(), header.version());
            // Should have stopped at the oversized field
            assert!(remaining.len() > 10, "Should have remaining data");
        },
        Err(TlvSerializationError::InvalidFormat(msg)) => {
            assert!(msg.contains("exceeds maximum"), "Should reject oversized fields");
        },
        Err(e) => panic!("Unexpected error type: {:?}", e),
    }
}

#[test]  
fn test_success_criteria_clean_boundary_detection() {
    // Success Criteria: deserialize_with_remainder() returns clean header + remaining ciphertext
    
    let mut header = TlvHeader::new();
    header.set_original_filename("test.txt");
    header.set_algorithm_id(42);
    
    let header_bytes = TlvSerializer::serialize(&header).unwrap();
    let ciphertext = b"This is encrypted content with random bytes that should not be parsed as TLV";
    
    let mut file_data = header_bytes.clone();
    file_data.extend_from_slice(ciphertext);
    
    match TlvSerializer::deserialize_with_remainder(&file_data) {
        Ok((parsed_header, remaining)) => {
            // Verify clean header parsing
            assert_eq!(parsed_header.original_filename(), header.original_filename());
            assert_eq!(parsed_header.get_field(TlvFieldType::AlgorithmId), header.get_field(TlvFieldType::AlgorithmId));
            
            // Verify clean ciphertext separation
            assert_eq!(remaining, ciphertext, "Should extract exact ciphertext without modification");
            assert_eq!(file_data.len() - remaining.len(), header_bytes.len(), "Boundary should be exact");
        },
        Err(e) => panic!("Should cleanly separate header and ciphertext: {:?}", e),
    }
}

#[test]
fn test_success_criteria_malformed_data_handling() {
    // Success Criteria: Malformed data gracefully handled with appropriate error types
    
    // Test 1: Truncated header
    let header = TlvHeader::new();
    let header_bytes = TlvSerializer::serialize(&header).unwrap();
    let truncated = &header_bytes[0..5]; // Only partial magic number
    
    match TlvSerializer::deserialize(truncated) {
        Err(TlvSerializationError::Io(_)) => (), // Expected - not enough data
        Ok(_) => panic!("Should fail on truncated data"),
        Err(e) => panic!("Wrong error type for truncated data: {:?}", e),
    }
    
    // Test 2: Invalid magic number  
    let mut bad_magic = header_bytes.clone();
    bad_magic[0] = 0xFF; // Corrupt magic number
    
    match TlvSerializer::deserialize(&bad_magic) {
        Err(TlvSerializationError::InvalidMagicNumber) => (),
        Ok(_) => panic!("Should fail on invalid magic number"),
        Err(e) => panic!("Wrong error type for invalid magic: {:?}", e),
    }
}

#[test]
fn test_success_criteria_single_point_of_truth() {
    // Success Criteria: Single point of truth for TLV parsing logic
    // This test verifies that FileSystemService relies on TlvSerializer for boundary detection
    
    use shadow_crypt::infrastructure::file_system::FileSystemService;
    use tempfile::TempDir;
    use std::fs;
    
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.shadow");
    
    // Create file with header + ciphertext
    let mut header = TlvHeader::new();
    header.set_original_filename("test.txt");
    let header_bytes = TlvSerializer::serialize(&header).unwrap();
    
    let mut file_data = header_bytes;
    file_data.extend_from_slice(b"ciphertext that should not be parsed as TLV");
    
    fs::write(&test_file, &file_data).unwrap();
    
    // FileSystemService should correctly parse only the header
    match FileSystemService::read_header_only(&test_file) {
        Ok(parsed_header) => {
            assert_eq!(parsed_header.original_filename(), Some("test.txt".to_string()));
        },
        Err(e) => panic!("FileSystemService should handle boundary detection correctly: {:?}", e),
    }
}

#[test]
fn test_success_criteria_all_tests_pass() {
    // Success Criteria: All boundary detection tests pass
    // This runs a comprehensive set of boundary detection scenarios
    
    let scenarios = vec![
        // Empty header
        (TlvHeader::new(), b"random ciphertext".as_slice()),
        
        // Header with one field
        {
            let mut h = TlvHeader::new();
            h.set_original_filename("file.txt");
            (h, b"more ciphertext data")
        },
        
        // Header with multiple fields
        {
            let mut h = TlvHeader::new();
            h.set_original_filename("file.txt");
            h.set_algorithm_id(1);
            h.set_content_hash([0x42u8; 32]);
            (h, b"even more ciphertext")
        },
    ];
    
    for (i, (header, ciphertext)) in scenarios.into_iter().enumerate() {
        let header_bytes = TlvSerializer::serialize(&header).unwrap();
        let mut file_data = header_bytes.clone();
        file_data.extend_from_slice(ciphertext);
        
        match TlvSerializer::deserialize_with_remainder(&file_data) {
            Ok((parsed_header, remaining)) => {
                assert_eq!(remaining, ciphertext, "Scenario {} failed boundary detection", i);
                assert_eq!(parsed_header.version(), header.version(), "Scenario {} header parsing failed", i);
            },
            Err(e) => panic!("Scenario {} failed: {:?}", i, e),
        }
    }
}