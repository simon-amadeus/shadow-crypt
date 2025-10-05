//! Tests for efficient streaming header parsing
//!
//! This validates that headers can be parsed from large files without loading
//! the entire file content into memory, ensuring both robustness and efficiency.

use shadow_crypt::domain::entities::tlv_header::TlvHeader;
use shadow_crypt::domain::services::tlv_parser::TlvParser;
use shadow_crypt::infrastructure::tlv_serialization::TlvSerializer;
use shadow_crypt::infrastructure::file_system::FileSystemService;
use std::io::{Write, Cursor, Read};
use tempfile::NamedTempFile;

#[test]
fn test_streaming_header_parsing_basic() {
    // Create a test header
    let mut header = TlvHeader::new();
    header.set_original_filename("test_file.txt");
    header.set_algorithm_id(1);
    header.set_content_hash([0x42u8; 32]);
    
    // Serialize header
    let header_bytes = TlvSerializer::serialize_header(&header).unwrap();
    
    // Create file data with header + large ciphertext
    let large_ciphertext = vec![0xFFu8; 1024 * 1024]; // 1MB of "ciphertext"
    let mut file_data = header_bytes.clone();
    file_data.extend_from_slice(&large_ciphertext);
    
    // Test streaming parsing
    let mut cursor = Cursor::new(&file_data);
    let parsed_header = TlvSerializer::parse_header_from_reader(&mut cursor).unwrap();
    
    // Verify header contents
    assert_eq!(parsed_header.original_filename(), Some("test_file.txt".to_string()));
    assert_eq!(parsed_header.algorithm_id(), Some(1));
    assert_eq!(parsed_header.content_hash(), Some([0x42u8; 32]));
    
    // Verify reader position is at start of ciphertext
    let current_pos = cursor.position() as usize;
    assert_eq!(current_pos, header_bytes.len());
    
    // Verify remaining data is the ciphertext
    let mut remaining = Vec::new();
    cursor.read_to_end(&mut remaining).unwrap();
    assert_eq!(remaining, large_ciphertext);
}

#[test]
fn test_streaming_file_system_integration() {
    // Create a test header
    let mut header = TlvHeader::new();
    header.set_original_filename("integration_test.txt");
    header.set_algorithm_id(2);
    
    // Create temporary file with header + ciphertext
    let mut temp_file = NamedTempFile::new().unwrap();
    let header_bytes = TlvSerializer::serialize_header(&header).unwrap();
    let ciphertext = b"This is encrypted content that should not be read during header parsing";
    
    temp_file.write_all(&header_bytes).unwrap();
    temp_file.write_all(ciphertext).unwrap();
    temp_file.flush().unwrap();
    
    // Test FileSystemService header-only reading
    let parsed_header = FileSystemService::read_header_only(temp_file.path()).unwrap();
    
    // Verify header was parsed correctly
    assert_eq!(parsed_header.original_filename(), Some("integration_test.txt".to_string()));
    assert_eq!(parsed_header.algorithm_id(), Some(2));
    
    // Verify content hash extraction works
    let content_hash = FileSystemService::extract_content_hash(temp_file.path()).unwrap();
    assert_eq!(content_hash, None); // No content hash was set
    
    // Verify file is recognized as Shadow file
    assert!(FileSystemService::is_shadow_file(temp_file.path()));
}

#[test]
fn test_streaming_boundary_detection() {
    // Create header with multiple fields
    let mut header = TlvHeader::new();
    header.set_original_filename("boundary_test.txt");
    header.set_algorithm_id(3);
    header.set_content_hash([0x12u8; 32]);
    
    let header_bytes = TlvSerializer::serialize_header(&header).unwrap();
    
    // Create ciphertext that looks like it could contain TLV fields
    let mut confusing_ciphertext = Vec::new();
    // Add some bytes that could be confused for field types
    confusing_ciphertext.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x05]); // Fake TLV field
    confusing_ciphertext.extend_from_slice(b"fake!");
    confusing_ciphertext.extend_from_slice(&[0x07, 0x00, 0x00, 0x00, 0x20]); // Another fake field
    confusing_ciphertext.extend_from_slice(&[0x99u8; 32]); // Fake content hash
    
    // Combine header and confusing ciphertext
    let mut file_data = header_bytes.clone();
    file_data.extend_from_slice(&confusing_ciphertext);
    
    // Parse with streaming reader
    let mut cursor = Cursor::new(&file_data);
    let parsed_header = TlvSerializer::parse_header_from_reader(&mut cursor).unwrap();
    
    // Verify only real header fields were parsed
    assert_eq!(parsed_header.original_filename(), Some("boundary_test.txt".to_string()));
    assert_eq!(parsed_header.algorithm_id(), Some(3));
    assert_eq!(parsed_header.content_hash(), Some([0x12u8; 32]));
    
    // Verify parser stopped at correct boundary
    let header_end_pos = cursor.position() as usize;
    assert_eq!(header_end_pos, header_bytes.len());
    
    // Verify ciphertext wasn't interpreted as header fields
    let mut remaining = Vec::new();
    cursor.read_to_end(&mut remaining).unwrap();
    assert_eq!(remaining, confusing_ciphertext);
}

#[test]
fn test_streaming_efficiency_large_file() {
    // Create test header
    let mut header = TlvHeader::new();
    header.set_original_filename("large_file_test.dat");
    header.set_algorithm_id(5);
    
    let header_bytes = TlvSerializer::serialize_header(&header).unwrap();
    
    // Simulate parsing from a very large file by using cursor with large capacity
    // but only providing header data + small amount of ciphertext
    let small_ciphertext = vec![0x00u8; 100]; // Only 100 bytes, not GB
    let mut file_data = header_bytes.clone();
    file_data.extend_from_slice(&small_ciphertext);
    
    let mut cursor = Cursor::new(&file_data);
    
    // This should complete quickly and only read header portion
    let start_time = std::time::Instant::now();
    let parsed_header = TlvSerializer::parse_header_from_reader(&mut cursor).unwrap();
    let parse_duration = start_time.elapsed();
    
    // Verify header parsed correctly
    assert_eq!(parsed_header.original_filename(), Some("large_file_test.dat".to_string()));
    assert_eq!(parsed_header.algorithm_id(), Some(5));
    
    // Verify parsing was efficient (should be nearly instantaneous)
    assert!(parse_duration.as_millis() < 100, "Streaming parse took too long: {:?}", parse_duration);
    
    // Verify position is correct
    assert_eq!(cursor.position() as usize, header_bytes.len());
}

#[test]
fn test_streaming_invalid_magic_number() {
    let invalid_data = b"Not a Shadow file at all!";
    let mut cursor = Cursor::new(invalid_data);
    
    // Should fail quickly on invalid magic number
    let result = TlvSerializer::parse_header_from_reader(&mut cursor);
    assert!(result.is_err());
    
    // Verify error type
    let error_string = format!("{:?}", result.unwrap_err());
    assert!(error_string.contains("InvalidMagicNumber"));
}

#[test]
fn test_streaming_truncated_file() {
    // Create partial header (just magic number, no version)
    let partial_data = &TlvHeader::MAGIC_NUMBER[..5]; // Only 5 bytes of magic
    let mut cursor = Cursor::new(partial_data);
    
    // Should handle truncated file gracefully
    let result = TlvSerializer::parse_header_from_reader(&mut cursor);
    assert!(result.is_err());
    
    // Should fail with corrupted structure error due to incomplete data
    let error_string = format!("{:?}", result.unwrap_err());
    assert!(error_string.contains("CorruptedStructure") || error_string.contains("Io"));
}