//! Integration test for shadows file detection across different versions
//! 
//! Tests that the `shadows` command can detect V2 (XChaCha20-Poly1305) 
//! encrypted files which are the current default format.

use shadow_crypt::listing::file_scanner::list_encrypted_files;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_shadows_detects_v2_files() {
    // Create temporary directory for test
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let temp_path = temp_dir.path();
    
    // Create mock V2 file (XChaCha20-Poly1305 format with "SHADOW2\0" magic) 
    let v2_file_path = temp_path.join("test_v2.txt.shadow");
    let v2_content = create_mock_v2_header();
    fs::write(&v2_file_path, v2_content).expect("Failed to write V2 test file");
    
    // Test file detection
    let password = "testpassword";
    
    let result = list_encrypted_files(temp_path, password);
    
    // The scan should complete without crashing and detect the V2 file
    // Note: Actual decryption may fail (expected for mock files), 
    // but detection should work
    match result {
        Ok(files) => {
            // Debug: Print what was found
            println!("DEBUG: Found {} files", files.len());
            for file in &files {
                println!("DEBUG: File: {}", file.obfuscated_name);
            }
            
            // Should detect at least 1 file (the V2 file)
            assert!(files.len() >= 1, "Should detect at least 1 encrypted file, found {}", files.len());
            
            // Check that the V2 file is detected
            let file_names: Vec<String> = files.iter()
                .map(|f| f.obfuscated_name.clone())
                .collect();
            
            assert!(file_names.contains(&"test_v2.txt.shadow".to_string()), 
                   "Should detect V2 file");
        }
        Err(e) => {
            // Even if password is wrong, files should still be detected
            // This test focuses on detection, not decryption
            panic!("File detection failed: {}", e);
        }
    }
}

/// Create minimal mock V2 header with "SHADOW2\0" magic number
fn create_mock_v2_header() -> Vec<u8> {
    let mut header = Vec::new();
    
    // Magic number (8 bytes): "SHADOW2\0"
    header.extend_from_slice(b"SHADOW2\0");
    
    // Version (2 bytes): 2
    header.extend_from_slice(&2u16.to_le_bytes());
    
    // Algorithm ID (2 bytes): XChaCha20-Poly1305 (2)
    header.extend_from_slice(&2u16.to_le_bytes());
    
    // Salt (32 bytes for V2)
    header.extend_from_slice(&[0u8; 32]);
    
    // Nonce length (1 byte)
    header.push(24); // XChaCha20 uses 24-byte nonce
    
    // Nonce (24 bytes)
    header.extend_from_slice(&[0u8; 24]);
    
    // Metadata length (2 bytes)
    header.extend_from_slice(&0u16.to_le_bytes());
    
    // Filename length (2 bytes)
    header.extend_from_slice(&0u16.to_le_bytes());
    
    // Add some dummy encrypted content
    header.extend_from_slice(b"dummy_encrypted_content_v2");
    
    header
}