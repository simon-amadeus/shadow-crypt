mod common;

use std::fs;
use std::time::{Duration, UNIX_EPOCH};

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

/// mtime and (on Unix) permissions must survive the round trip via the v3
/// metadata envelope.
#[test]
fn test_round_trip_preserves_metadata() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("meta.txt");
    fs::write(&input_file, b"metadata test").unwrap();

    let mtime = UNIX_EPOCH + Duration::new(1_600_000_000, 0);
    let f = fs::File::open(&input_file).unwrap();
    f.set_modified(mtime).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&input_file, fs::Permissions::from_mode(0o640)).unwrap();
    }
    drop(f);

    encrypt_files(&[&input_file], TEST_PASSWORD, temp_dir.path()).unwrap();
    let encrypted_file = find_single_shadow_file(temp_dir.path());
    fs::remove_file(&input_file).unwrap();

    decrypt_files(&[&encrypted_file], TEST_PASSWORD, temp_dir.path()).unwrap();

    let restored = fs::metadata(&input_file).unwrap();
    assert_eq!(restored.modified().unwrap(), mtime);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(restored.permissions().mode() & 0o7777, 0o640);
    }
}

/// Chunking edge cases: empty content and content spanning multiple chunks
/// must round-trip byte for byte.
#[test]
fn test_round_trip_empty_and_multi_chunk_files() {
    let multi_chunk = vec![0xabu8; 3 * 1024 * 1024 + 17]; // > 3 stream chunks
    for content in [b"".to_vec(), multi_chunk] {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("data.bin");
        fs::write(&input_file, &content).unwrap();

        encrypt_files(&[&input_file], TEST_PASSWORD, temp_dir.path()).unwrap();
        let encrypted_file = find_single_shadow_file(temp_dir.path());
        fs::remove_file(&input_file).unwrap();

        decrypt_files(&[&encrypted_file], TEST_PASSWORD, temp_dir.path()).unwrap();
        assert_eq!(fs::read(&input_file).unwrap(), content);
    }
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
