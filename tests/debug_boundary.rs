//! Debug the find_tlv_section_end function

use shadow_crypt::domain::entities::tlv_header::TlvHeader;
use shadow_crypt::infrastructure::tlv_serialization::TlvSerializer;

#[test]
fn test_boundary_detection_debug() {
    // Create an empty header
    let header = TlvHeader::new();
    let header_bytes = TlvSerializer::serialize(&header).expect("Failed to serialize");
    
    println!("Empty header bytes: {:?}", header_bytes);
    println!("Length: {}", header_bytes.len());
    
    // Create file data with header + ciphertext
    let mut file_data = header_bytes.clone();
    file_data.extend_from_slice(b"ciphertext");
    
    println!("File data with ciphertext: {:?}", file_data);
    println!("Length: {}", file_data.len());
    
    // Test boundary detection manually - we can't call the private method directly
    // but we can test the logic
    
    // Magic + version = 10 bytes
    // Empty header should end at position 10
    
    let pos = 10; // Start after magic + version
    
    if file_data.len() <= 10 {
        println!("Only magic + version, header ends at 10");
    } else {
        println!("Have data beyond magic + version");
        
        if pos < file_data.len() {
            // Check if we can read a TLV field type
            if pos + 5 > file_data.len() {
                println!("Not enough data for TLV field header, header ends at {}", pos);
            } else {
                let field_type_raw = file_data[pos];
                println!("First byte after header: 0x{:02x} ({})", field_type_raw, field_type_raw as char);
                
                // Check if it's a valid TLV field type (0x01-0x0A or 0xFF)
                let is_valid = (0x01..=0x0A).contains(&field_type_raw) || field_type_raw == 0xFF;
                println!("Is valid TLV field type: {}", is_valid);
                
                if !is_valid {
                    println!("Not a valid TLV field, header ends at {}", pos);
                } else {
                    println!("Looks like a valid TLV field type");
                }
            }
        }
    }
}