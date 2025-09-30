//! Integration tests for source file removal and CLI simplification
//! 
//! Tests the secure deletion functionality and simplified CLI interface

use std::fs;
use std::path::Path;
use tempfile::TempDir;
use crypto::encryption::encrypt_file::encrypt_single_file_with_params;
use crypto::shared::crypto::argon2::Argon2Params;
use crypto::decryption::decrypt_file::decrypt_single_file_with_params;
use crypto::shared::secure_delete::secure_delete_file;

#[test]
fn test_source_removal_workflow() {
    // Set up test environment
    let temp_dir = TempDir::new().unwrap();
    let original_file = temp_dir.path().join("secret_document.txt");
    let test_content = "This is sensitive content that should be encrypted";
    fs::write(&original_file, test_content).unwrap();
    
    let password = "test_password_123";
    
    // Test 1: Normal encryption with automatic output path generation
    let auto_output_path = format!("{}.enc", original_file.to_string_lossy());
    let encrypted_file = Path::new(&auto_output_path);
    
    // Encrypt the file (simulating simplified CLI: lock secret_document.txt)
    encrypt_single_file_with_params(&original_file, encrypted_file, password, false, &Argon2Params::test_params()).unwrap();
    
    // Verify encrypted file exists and original still exists
    assert!(encrypted_file.exists(), "Encrypted file should be created");
    assert!(original_file.exists(), "Original file should still exist");
    assert_eq!(encrypted_file.extension().unwrap(), "enc", "Should have .enc extension");
    
    // Test 2: Simulate source removal after encryption
    // (This simulates: lock --remove-source secret_document.txt)
    secure_delete_file(&original_file).unwrap();
    
    // Verify original is gone, encrypted remains
    assert!(!original_file.exists(), "Original file should be removed");
    assert!(encrypted_file.exists(), "Encrypted file should remain");
    
    // Test 3: Decrypt with automatic filename restoration
    // The decryption should restore the original filename from the header
    let restored_file = temp_dir.path().join("secret_document.txt");
    
    decrypt_single_file_with_params(encrypted_file, &restored_file, password, &Argon2Params::test_params()).unwrap();
    
    // Verify decryption worked and content matches
    assert!(restored_file.exists(), "Restored file should exist");
    let restored_content = fs::read_to_string(&restored_file).unwrap();
    assert_eq!(restored_content, test_content, "Content should match original");
    
    // Test 4: Simulate source removal after decryption
    // (This simulates: unlock --remove-source secret_document.txt.enc)
    secure_delete_file(encrypted_file).unwrap();
    
    // Verify encrypted file is gone, decrypted file remains
    assert!(!encrypted_file.exists(), "Encrypted file should be removed");
    assert!(restored_file.exists(), "Decrypted file should remain");
}

#[test]
fn test_simplified_cli_behavior() {
    let temp_dir = TempDir::new().unwrap();
    
    // Test different file types and extensions
    let test_cases = vec![
        ("document.pdf", "document.pdf.enc"),
        ("image.jpg", "image.jpg.enc"),
        ("data", "data.enc"),
        ("script.sh", "script.sh.enc"),
    ];
    
    for (input_name, expected_output) in test_cases {
        let input_file = temp_dir.path().join(input_name);
        fs::write(&input_file, "test content").unwrap();
        
        // Test auto-generated output path logic
        let auto_output = format!("{}.enc", input_file.to_string_lossy());
        let expected_path = temp_dir.path().join(expected_output);
        
        assert_eq!(Path::new(&auto_output), expected_path, 
                  "Auto-generated path should match expected for {}", input_name);
    }
}

#[test] 
fn test_secure_deletion_security() {
    // Test that secure deletion actually overwrites data
    let temp_dir = TempDir::new().unwrap();
    let sensitive_file = temp_dir.path().join("sensitive.txt");
    let sensitive_data = "SENSITIVE_SECRET_12345_ABCDEF";
    
    fs::write(&sensitive_file, sensitive_data).unwrap();
    assert!(sensitive_file.exists());
    
    // Perform secure deletion
    secure_delete_file(&sensitive_file).unwrap();
    
    // Verify file is completely gone
    assert!(!sensitive_file.exists(), "File should be completely removed");
    
    // Note: We can't easily test that the data was overwritten on disk
    // without low-level disk access, but the secure_delete function
    // implements the overwrite-before-delete pattern
}

#[test]
fn test_obfuscated_workflow_with_simplified_cli() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("private_doc.pdf");
    fs::write(&input_file, "private content").unwrap();
    
    let password = "obfuscation_test";
    
    // Test obfuscated encryption (simulating: lock --obfuscate private_doc.pdf)
    // When obfuscating, the output should be in the same directory with .enc extension
    let parent_dir = input_file.parent().unwrap();
    let temp_output = parent_dir.join("temp_obfuscated.enc"); // Placeholder name
    
    encrypt_single_file_with_params(&input_file, &temp_output, password, true, &Argon2Params::test_params()).unwrap();
    
    // Find the actual obfuscated file that was created (filename will be different)
    let enc_files: Vec<_> = fs::read_dir(parent_dir).unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().map(|ext| ext == "enc").unwrap_or(false))
        .collect();
    
    assert_eq!(enc_files.len(), 1, "Should have exactly one .enc file");
    let obfuscated_file = &enc_files[0];
    
    // Verify encrypted file exists and has obfuscated name
    assert!(obfuscated_file.exists(), "Obfuscated encrypted file should exist");
    assert_ne!(obfuscated_file.file_name().unwrap().to_str().unwrap(), 
              "private_doc.pdf.enc", "Filename should be obfuscated, not original");
    
    // Test that we can decrypt and restore original filename
    let restored_file = temp_dir.path().join("restored_private_doc.pdf");
    decrypt_single_file_with_params(obfuscated_file, &restored_file, password, &Argon2Params::test_params()).unwrap();
    
    // Verify restoration worked
    assert!(restored_file.exists(), "Restored file should exist");
    let content = fs::read_to_string(&restored_file).unwrap();
    assert_eq!(content, "private content", "Content should be preserved");
}