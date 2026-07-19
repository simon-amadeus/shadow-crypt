mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{TEST_PASSWORD, decrypt_files, encrypt_files, find_single_shadow_file};
use tempfile::TempDir;

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Decrypts a committed fixture file and checks filename and content.
/// Guards against changes that would break decryption of existing files.
fn assert_fixture_decrypts(fixture_name: &str, expected_filename: &str, expected_content: &[u8]) {
    let temp_dir = TempDir::new().unwrap();
    let fixture = fixture_path(fixture_name);
    assert!(fixture.exists(), "Fixture not found at {:?}", fixture);

    let temp_shadow_file = temp_dir.path().join(fixture_name);
    fs::copy(&fixture, &temp_shadow_file).unwrap();

    decrypt_files(&[&temp_shadow_file], TEST_PASSWORD, temp_dir.path()).unwrap();

    let decrypted_file = temp_dir.path().join(expected_filename);
    assert!(decrypted_file.exists(), "Decrypted file was not created");

    let decrypted_content = fs::read(&decrypted_file).unwrap();
    assert_eq!(
        decrypted_content, expected_content,
        "Decrypted content does not match expected content"
    );
}

#[test]
fn test_v1_backward_compatibility() {
    assert_fixture_decrypts(
        "test_v1.shadow",
        "test_v1_plaintext.txt",
        b"This is a test file for backward compatibility testing. It contains known content that should be decrypted correctly.\n",
    );
}

#[test]
fn test_v2_backward_compatibility() {
    assert_fixture_decrypts(
        "test_v2.shadow",
        "test_v2_plaintext.txt",
        b"This is a test file for v2 backward compatibility testing. It contains known content that should be decrypted correctly.\n",
    );
}

/// Regenerates the v2 fixture. Run manually after an intentional format
/// change: `cargo test regenerate_v2_fixture -- --ignored`
#[test]
#[ignore]
fn regenerate_v2_fixture() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("test_v2_plaintext.txt");
    fs::write(
        &input_file,
        b"This is a test file for v2 backward compatibility testing. It contains known content that should be decrypted correctly.\n",
    )
    .unwrap();

    encrypt_files(&[&input_file], TEST_PASSWORD, temp_dir.path()).unwrap();
    let encrypted = find_single_shadow_file(temp_dir.path());

    fs::copy(&encrypted, fixture_path("test_v2.shadow")).unwrap();
}
