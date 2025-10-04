//! Debug empty header case

use shadow_crypt::domain::entities::tlv_header::TlvHeader;
use shadow_crypt::infrastructure::file_system::FileSystemService;
use tempfile::TempDir;
use std::fs;

#[test]
fn test_empty_header_debug() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let test_file_path = temp_dir.path().join("empty_header.shadow");
    
    // Create an empty header (no TLV fields)
    let header = TlvHeader::new();
    
    // Write using FileSystemService 
    FileSystemService::write_encrypted_file(&test_file_path, &header, b"test")
        .expect("Failed to write file with empty header");
    
    println!("Written file with empty header");
    
    // Check what was actually written
    let file_data = fs::read(&test_file_path).expect("Failed to read file");
    println!("File contents: {:?}", file_data);
    println!("File length: {} bytes", file_data.len());
    
    // Test is_shadow_file
    let is_shadow = FileSystemService::is_shadow_file(&test_file_path);
    println!("is_shadow_file returned: {}", is_shadow);
    
    if !is_shadow {
        // Debug what went wrong
        match FileSystemService::read_header_only(&test_file_path) {
            Ok(read_header) => {
                println!("read_header_only succeeded");
                println!("Read header magic: {:?}", read_header.magic_number());
                println!("Read header version: {}", read_header.version());
            },
            Err(e) => println!("read_header_only failed: {:?}", e),
        }
    }
    
    assert!(is_shadow, "Empty header should still be detected as Shadow file");
}