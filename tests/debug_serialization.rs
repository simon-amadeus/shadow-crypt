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
    
    // This should fail because it tries to read the ciphertext as TLV
    match TlvSerializer::deserialize(&file_data) {
        Ok(_) => println!("File data with ciphertext deserializes successfully (unexpected!)"),
        Err(e) => println!("File data with ciphertext deserialization failed (expected): {:?}", e),
    }
    
    // The issue is that TlvSerializer::deserialize expects to consume the entire buffer
    // but we only want to consume the header portion
}