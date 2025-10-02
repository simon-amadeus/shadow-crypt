//! Integration tests for double-encryption prevention
//! 
//! Tests to ensure the system prevents encrypting already encrypted files

use std::fs::File;
use std::io::Write;
use tempfile::tempdir;
use shadow_crypt::encryption::{encrypt_single_file_with_params};
use shadow_crypt::shared::algorithms::aes_gcm::Argon2Params;
use shadow_crypt::shared::file_detection::is_encrypted_file;

#[test]
fn test_is_encrypted_file_detection() {
    let dir = tempdir().unwrap();
    
    // Create a plain text file
    let plain_file = dir.path().join("plain.txt");
    let mut file = File::create(&plain_file).unwrap();
    writeln!(file, "This is plain text").unwrap();
    
    // Should not be detected as encrypted
    assert_eq!(is_encrypted_file(&plain_file).unwrap(), false);
    
    // Encrypt the file
    let encrypted_file = dir.path().join("plain.txt.shadow");
    let fast_params = Argon2Params::test_params(); // Use fast parameters for testing
    encrypt_single_file_with_params(&plain_file, &encrypted_file, "password123", false, &fast_params).unwrap();
    
    // Should now be detected as encrypted
    assert_eq!(is_encrypted_file(&encrypted_file).unwrap(), true);
    
    // Plain file should still not be encrypted
    assert_eq!(is_encrypted_file(&plain_file).unwrap(), false);
}

#[test]
fn test_is_encrypted_file_empty_file() {
    let dir = tempdir().unwrap();
    let empty_file = dir.path().join("empty.txt");
    File::create(&empty_file).unwrap();
    
    // Empty file should not be detected as encrypted
    assert_eq!(is_encrypted_file(&empty_file).unwrap(), false);
}

#[test]
fn test_is_encrypted_file_short_file() {
    let dir = tempdir().unwrap();
    let short_file = dir.path().join("short.txt");
    let mut file = File::create(&short_file).unwrap();
    write!(file, "Hi").unwrap(); // Only 2 bytes, less than magic header
    
    // Short file should not be detected as encrypted
    assert_eq!(is_encrypted_file(&short_file).unwrap(), false);
}

#[test]
fn test_is_encrypted_file_fake_header() {
    let dir = tempdir().unwrap();
    let fake_file = dir.path().join("fake.txt");
    let mut file = File::create(&fake_file).unwrap();
    write!(file, "SHADOW but not really encrypted").unwrap();
    
    // File starting with "SHADOW" should be detected as encrypted
    // (This is expected behavior - we err on the side of caution)
    assert_eq!(is_encrypted_file(&fake_file).unwrap(), true);
}

#[test]
fn test_is_encrypted_file_nonexistent() {
    let dir = tempdir().unwrap();
    let nonexistent = dir.path().join("does_not_exist.txt");
    
    // Should return an error for nonexistent file
    assert!(is_encrypted_file(&nonexistent).is_err());
}