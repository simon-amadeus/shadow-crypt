//! Integration test for EncryptionService with FileDetector
//! Tests double-encryption prevention functionality

use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

use shadow_crypt::domain::services::{EncryptionService, EncryptionOptions};
use shadow_crypt::domain::errors::DomainError;
use shadow_crypt::infrastructure::crypto::factory::Algorithm;

#[test]
fn test_encryption_service_prevents_double_encryption() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    
    // Create a plaintext test file
    let plaintext_path = temp_dir.path().join("test.txt");
    let mut file = File::create(&plaintext_path).expect("Failed to create test file");
    file.write_all(b"This is test content").expect("Failed to write test content");
    drop(file);
    
    // Create paths for encrypted files
    let encrypted_path = temp_dir.path().join("test.txt.shadow");
    let double_encrypted_path = temp_dir.path().join("test.txt.shadow.shadow");
    
    // Create encryption service
    let mut service = EncryptionService::new();
    let algorithm = Algorithm::default();
    let password = "test_password";
    let options = EncryptionOptions {
        obfuscate_filename: false,
        force_overwrite: false,
        remove_source: false,
        check_duplicates: false,
    };
    
    // First encryption should succeed
    let result = service.encrypt_file(
        &plaintext_path,
        &encrypted_path,
        &algorithm,
        password,
        options.clone(),
    );
    
    assert!(result.is_ok(), "First encryption should succeed");
    assert!(encrypted_path.exists(), "Encrypted file should exist");
    
    // Attempting to encrypt the already encrypted file should fail
    let result = service.encrypt_file(
        &encrypted_path,
        &double_encrypted_path,
        &algorithm,
        password,
        options.clone(),
    );
    
    assert!(result.is_err(), "Second encryption should fail due to double-encryption prevention");
    
    // Verify the error type
    match result.unwrap_err() {
        DomainError::DoubleEncryptionPrevention(_) => {
            // Expected error type
        }
        other => panic!("Expected DoubleEncryptionPrevention error, got: {:?}", other),
    }
    
    // Double-encrypted file should not exist
    assert!(!double_encrypted_path.exists(), "Double-encrypted file should not exist");
}

#[test]
fn test_encryption_service_with_force_overwrite() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    
    // Create a plaintext test file
    let plaintext_path = temp_dir.path().join("test.txt");
    let mut file = File::create(&plaintext_path).expect("Failed to create test file");
    file.write_all(b"This is test content").expect("Failed to write test content");
    drop(file);
    
    // Create an encrypted file first
    let encrypted_path = temp_dir.path().join("test.txt.shadow");
    let double_encrypted_path = temp_dir.path().join("test.txt.shadow.shadow");
    
    let mut service = EncryptionService::new();
    let algorithm = Algorithm::default();
    let password = "test_password";
    
    // First encryption
    let options = EncryptionOptions {
        obfuscate_filename: false,
        force_overwrite: false,
        remove_source: false,
        check_duplicates: false,
    };
    
    service.encrypt_file(&plaintext_path, &encrypted_path, &algorithm, password, options).unwrap();
    
    // Now try to encrypt with force_overwrite = true
    let force_options = EncryptionOptions {
        obfuscate_filename: false,
        force_overwrite: true,  // This should allow overwriting
        remove_source: false,
        check_duplicates: false,
    };
    
    let result = service.encrypt_file(
        &encrypted_path,
        &double_encrypted_path,
        &algorithm,
        password,
        force_options,
    );
    
    // With force_overwrite, it should succeed (though the resulting file would be double-encrypted)
    assert!(result.is_ok(), "Encryption with force_overwrite should succeed");
    assert!(double_encrypted_path.exists(), "Force-encrypted file should exist");
}