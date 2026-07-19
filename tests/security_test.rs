mod common;

use std::fs;

use common::{TEST_PASSWORD, encrypt_files, find_single_shadow_file};
use tempfile::TempDir;

/// Encrypts a single file and returns the raw bytes of the encrypted output.
fn encrypted_bytes_for(filename: &str, content: &[u8]) -> Vec<u8> {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join(filename);
    fs::write(&input_file, content).unwrap();

    encrypt_files(&[&input_file], TEST_PASSWORD, temp_dir.path()).unwrap();

    fs::read(find_single_shadow_file(temp_dir.path())).unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn test_filename_is_encrypted_in_header() {
    let filename = "sensitive_document.txt";
    let encrypted_bytes = encrypted_bytes_for(filename, b"This is sensitive content.");

    assert!(!encrypted_bytes.is_empty(), "Encrypted file is empty");
    assert!(
        !contains(&encrypted_bytes, filename.as_bytes()),
        "Filename appears as plaintext in the encrypted file, which violates security requirements"
    );
}

#[test]
fn test_content_is_encrypted_in_file() {
    let content = b"This is highly confidential information that should never appear in plaintext.";
    let encrypted_bytes = encrypted_bytes_for("secret.txt", content);

    assert!(!encrypted_bytes.is_empty(), "Encrypted file is empty");
    assert!(
        !contains(&encrypted_bytes, content),
        "Original content appears as plaintext in the encrypted file, which violates security requirements"
    );
}
