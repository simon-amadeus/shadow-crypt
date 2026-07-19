mod common;

use std::fs;

use common::{TEST_PASSWORD, decrypt_files, encrypt_files, find_single_shadow_file};
use tempfile::TempDir;

#[test]
fn test_encrypt_decrypt_round_trip() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("test.txt");
    let test_content = b"Hello, World! This is a test file.";
    fs::write(&input_file, test_content).unwrap();

    encrypt_files(&[&input_file], TEST_PASSWORD, temp_dir.path()).unwrap();
    let encrypted_file = find_single_shadow_file(temp_dir.path());

    // Remove the original so decryption can restore it (no-overwrite policy)
    // and so the final comparison actually checks the decrypted output.
    fs::remove_file(&input_file).unwrap();

    decrypt_files(&[&encrypted_file], TEST_PASSWORD, temp_dir.path()).unwrap();

    let decrypted_content = fs::read(&input_file).unwrap();
    assert_eq!(
        test_content.to_vec(),
        decrypted_content,
        "Decrypted content does not match original"
    );
}

#[test]
fn test_decrypt_with_wrong_password_reports_failure() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("secret.txt");
    fs::write(&input_file, b"sensitive data").unwrap();

    encrypt_files(&[&input_file], "correct password", temp_dir.path()).unwrap();
    let encrypted_file = find_single_shadow_file(temp_dir.path());

    // The workflow must surface per-file failures so the CLI exits nonzero.
    let result = decrypt_files(&[&encrypted_file], "wrong password", temp_dir.path());
    assert!(result.is_err(), "wrong password should fail the workflow");
}
