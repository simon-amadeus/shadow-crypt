//! Deep debug of empty header serialization

use shadow_crypt::domain::entities::tlv_header::TlvHeader;
use shadow_crypt::infrastructure::tlv_serialization::TlvSerializer;

#[test]
fn test_empty_header_serialization_debug() {
    // Create an empty header
    let header = TlvHeader::new();
    
    // Serialize it
    let header_bytes = TlvSerializer::serialize(&header).expect("Failed to serialize empty header");
    
    println!("Empty header serialized to {} bytes", header_bytes.len());
    println!("Header bytes: {:?}", header_bytes);
    
    // Try to deserialize it back
    match TlvSerializer::deserialize(&header_bytes) {
        Ok(_) => println!("Empty header deserializes successfully"),
        Err(e) => println!("Empty header deserialization failed: {:?}", e),
    }
    
    // Now test with extra data (simulating ciphertext)
    let mut file_data = header_bytes.clone();
    file_data.extend_from_slice(b"some ciphertext data");
    
    println!("File data with ciphertext: {} bytes", file_data.len());
    
    // With robust boundary detection, this should succeed by parsing only the header
    match TlvSerializer::deserialize(&file_data) {
        Ok(_) => println!("✅ File data with ciphertext deserializes successfully (correct behavior with robust boundary detection)"),
        Err(e) => println!("❌ File data with ciphertext deserialization failed (unexpected): {:?}", e),
    }
    
    // Test that deserialize_with_remainder correctly separates header from ciphertext
    match TlvSerializer::deserialize_with_remainder(&file_data) {
        Ok((_, remaining)) => {
            println!("✅ Header/ciphertext boundary correctly detected");
            println!("Ciphertext portion: {} bytes", remaining.len());
            assert_eq!(remaining, b"some ciphertext data", "Should extract exact ciphertext");
        },
        Err(e) => {
            println!("❌ deserialize_with_remainder failed: {:?}", e);
        }
    }
}