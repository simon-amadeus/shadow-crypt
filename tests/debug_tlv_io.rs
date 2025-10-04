//! Simple test to debug TLV header I/O issues

use shadow_crypt::domain::entities::tlv_header::TlvHeader;
use shadow_crypt::infrastructure::tlv_serialization::TlvSerializer;
use shadow_crypt::infrastructure::file_system::FileSystemService;
use tempfile::TempDir;
use std::fs;

#[test]
fn test_tlv_file_io_debug() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let test_file_path = temp_dir.path().join("debug.shadow");
    
    // Create a simple header with one field
    let mut header = TlvHeader::new();
    header.set_original_filename("test.txt");
    
    // Write header using TlvSerializer directly to a file  
    let header_bytes = TlvSerializer::serialize(&header).expect("Failed to serialize header");
    let ciphertext = b"Hello, World!";
    
    // Write file manually
    let mut file_contents = Vec::new();
    file_contents.extend_from_slice(&header_bytes);
    file_contents.extend_from_slice(ciphertext);
    
    fs::write(&test_file_path, &file_contents).expect("Failed to write test file");
    
    println!("Written file size: {} bytes", file_contents.len());
    println!("Header size: {} bytes", header_bytes.len());
    println!("Ciphertext size: {} bytes", ciphertext.len());
    
    // Try to read header back
    match FileSystemService::read_header_only(&test_file_path) {
        Ok(read_header) => {
            println!("Successfully read header");
            assert_eq!(read_header.original_filename(), Some("test.txt".to_string()));
        }
        Err(e) => {
            panic!("Failed to read header: {:?}", e);
        }
    }
    
    // Test is_shadow_file
    println!("Testing is_shadow_file...");
    match FileSystemService::is_shadow_file(&test_file_path) {
        true => println!("is_shadow_file returned true"),
        false => {
            println!("is_shadow_file returned false - this is the bug!");
            
            // Debug: Try reading the file manually to see what's wrong
            let file_data = fs::read(&test_file_path).expect("Failed to read file");
            println!("File data length: {}", file_data.len());
            println!("First 20 bytes: {:?}", &file_data[0..20.min(file_data.len())]);
        }
    }
    
    assert!(FileSystemService::is_shadow_file(&test_file_path), "is_shadow_file should return true");
}