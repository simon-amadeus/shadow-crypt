use shadow_crypt::domain::services::{EncryptionService, EncryptionOptions};
use shadow_crypt::domain::utilities::content_hash::calculate_content_hash;
use shadow_crypt::infrastructure::file_system::FileSystemService;
use shadow_crypt::infrastructure::crypto::xchacha20_poly1305::XChaCha20Poly1305Config;
use std::io::Write;
use tempfile::{NamedTempFile, TempDir};

#[test]
fn test_encryption_service_content_hash_integration() {
    // Setup test environment
    let temp_dir = TempDir::new().unwrap();
    let search_paths = vec![temp_dir.path().to_path_buf()];

    // Create EncryptionService with duplicate detection enabled  
    let mut encryption_service = EncryptionService::new()
        .with_duplicate_detection(search_paths)
        .with_progress_reporting(true);

    // Create test file with specific content
    let mut test_file = NamedTempFile::new_in(temp_dir.path()).unwrap();
    let test_content = b"This is test content for content hash integration testing";
    test_file.write_all(test_content).unwrap();
    test_file.flush().unwrap();

    // Calculate expected content hash manually for verification
    let expected_hash = calculate_content_hash(test_content);

    // Setup encryption parameters
    let output_path = temp_dir.path().join("test_file.shadow");
    let algorithm = XChaCha20Poly1305Config::new(
        shadow_crypt::infrastructure::crypto::xchacha20_poly1305::Argon2Params::test()
    );
    let password = "test_password_123";
    let options = EncryptionOptions {
        obfuscate_filename: false,
        force_overwrite: false,
        remove_source: false,
        check_duplicates: true,
    };

    // Execute encryption
    let result = encryption_service.encrypt_file(
        test_file.path(),
        &output_path,
        &algorithm,
        password,
        options.clone(),
    ).expect("Encryption should succeed");

    // Verify EncryptionResult contains correct content hash
    assert_eq!(result.content_hash, expected_hash, "EncryptionResult should contain correct content hash");

    // Verify encrypted file exists
    assert!(output_path.exists(), "Encrypted file should exist");

    // Verify content hash is stored in TLV header
    let header = FileSystemService::read_header_only(&output_path).expect("Should read TLV header");
    
    let stored_hash = header.content_hash().expect("TLV header should contain content hash");
    assert_eq!(stored_hash, expected_hash, "TLV header should contain correct content hash");

    // Test duplicate detection by encrypting same content again
    let mut duplicate_file = NamedTempFile::new_in(temp_dir.path()).unwrap();
    duplicate_file.write_all(test_content).unwrap();
    duplicate_file.flush().unwrap();

    let output_path2 = temp_dir.path().join("duplicate_file.shadow");
    
    // This should detect the duplicate and log warning messages
    let result2 = encryption_service.encrypt_file(
        duplicate_file.path(),
        &output_path2,
        &algorithm,
        password,
        options.clone(),
    ).expect("Encryption should succeed even with duplicates");

    // Verify same content hash for duplicate content
    assert_eq!(result2.content_hash, expected_hash, "Duplicate content should have same hash");

    // Verify both encrypted files exist
    assert!(output_path.exists(), "First encrypted file should exist");
    assert!(output_path2.exists(), "Second encrypted file should exist");
}

#[test]
fn test_content_hash_persistence_through_encryption_cycle() {
    // Test that content hash persists correctly through the entire encrypt/decrypt cycle
    let temp_dir = TempDir::new().unwrap();
    
    // Create test file
    let mut test_file = NamedTempFile::new_in(temp_dir.path()).unwrap();
    let test_content = b"Persistence test content for hash validation";
    test_file.write_all(test_content).unwrap();
    test_file.flush().unwrap();

    // Calculate original content hash
    let original_hash = calculate_content_hash(test_content);

    // Encrypt file
    let mut encryption_service = EncryptionService::new();
    let output_path = temp_dir.path().join("persistence_test.shadow");
    let algorithm = XChaCha20Poly1305Config::new(
        shadow_crypt::infrastructure::crypto::xchacha20_poly1305::Argon2Params::test()
    );
    let password = "persistence_test_password";
    
    let options = EncryptionOptions {
        obfuscate_filename: false,
        force_overwrite: false,
        remove_source: false,
        check_duplicates: false,
    };

    let encryption_result = encryption_service.encrypt_file(
        test_file.path(),
        &output_path,
        &algorithm,
        password,
        options,
    ).expect("Encryption should succeed");

    // Verify content hash in result
    assert_eq!(encryption_result.content_hash, original_hash, "Encryption result should preserve content hash");

    // Read encrypted file and verify TLV header contains hash
    let header = FileSystemService::read_header_only(&output_path).expect("Should read TLV header");
    
    let tlv_hash = header.content_hash().expect("TLV header should contain content hash");
    assert_eq!(tlv_hash, original_hash, "TLV header should preserve original content hash");

    // Verify hash matches original content, not encrypted content  
    let encrypted_data = std::fs::read(&output_path).expect("Should read encrypted file");
    let encrypted_content_hash: [u8; 32] = {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&encrypted_data);
        let hash_bytes = hasher.finalize();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes);
        hash_array
    };
    
    assert_ne!(tlv_hash, encrypted_content_hash, "Content hash should be of plaintext, not ciphertext");
}

#[test]
fn test_multiple_files_with_unique_content_hashes() {
    // Test batch encryption with multiple files having different content
    let temp_dir = TempDir::new().unwrap();
    let search_paths = vec![temp_dir.path().to_path_buf()];
    
    let mut encryption_service = EncryptionService::new()
        .with_duplicate_detection(search_paths)
        .with_progress_reporting(false);

    // Create multiple files with different content
    let mut file_pairs = Vec::new();
    let mut expected_hashes = Vec::new();
    let mut temp_files = Vec::new(); // Keep files alive

    for i in 0..3 {
        let mut temp_file = NamedTempFile::new_in(temp_dir.path()).unwrap();
        let content = format!("Unique content for file number {}", i);
        temp_file.write_all(content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        // Calculate expected hash
        let expected_hash = calculate_content_hash(content.as_bytes());
        expected_hashes.push(expected_hash);

        let output_path = temp_dir.path().join(format!("file_{}.shadow", i));
        file_pairs.push((temp_file.path().to_path_buf(), output_path));
        temp_files.push(temp_file); // Keep file alive
    }

    // Encrypt all files in batch
    let algorithm = XChaCha20Poly1305Config::new(
        shadow_crypt::infrastructure::crypto::xchacha20_poly1305::Argon2Params::test()
    );
    let password = "batch_test_password";
    let options = EncryptionOptions {
        obfuscate_filename: false,
        force_overwrite: false,
        remove_source: false,
        check_duplicates: true,
    };

    let batch_result = encryption_service.encrypt_multiple_files(
        file_pairs,
        &algorithm,
        password,
        options,
    ).expect("Batch encryption should succeed");

    // Verify all files encrypted successfully
    assert_eq!(batch_result.successful.len(), 3, "All 3 files should encrypt successfully");
    assert_eq!(batch_result.failed.len(), 0, "No files should fail");

    // Verify each file has correct content hash
    for (i, result) in batch_result.successful.iter().enumerate() {
        assert_eq!(result.content_hash, expected_hashes[i], "File {} should have correct content hash", i);
        
        // Verify TLV header in each encrypted file
        let header = FileSystemService::read_header_only(&result.output_path).expect("Should read TLV header");
        
        let tlv_hash = header.content_hash().expect("TLV header should contain content hash");
        assert_eq!(tlv_hash, expected_hashes[i], "TLV header for file {} should have correct hash", i);
    }

    // Verify all content hashes are unique
    let unique_hashes: std::collections::HashSet<_> = batch_result.successful.iter()
        .map(|r| r.content_hash)
        .collect();
    assert_eq!(unique_hashes.len(), 3, "All content hashes should be unique");
}