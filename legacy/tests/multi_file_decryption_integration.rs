//! Multi-file decryption integration tests
//! 
//! Tests multi-file decryption functionality including glob patterns,
//! progress reporting, and error handling.

use shadow_crypt::decryption::{decrypt_multiple_files_with_provider, expand_glob_patterns};
use shadow_crypt::encryption::encrypt_file::encrypt_single_file_with_config;
use shadow_crypt::shared::algorithms::{AesGcmConfig, DefaultConfigProvider, CryptoConfig};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_decrypt_multiple_files_success() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let temp_path = temp_dir.path();
    
    // Create test files
    let file1 = temp_path.join("test1.txt");
    let file2 = temp_path.join("test2.txt");
    fs::write(&file1, "Content of file 1").expect("Failed to write test file 1");
    fs::write(&file2, "Content of file 2").expect("Failed to write test file 2");
    
    // Encrypt both files
    let encrypted1 = temp_path.join("test1.txt.shadow");
    let encrypted2 = temp_path.join("test2.txt.shadow");
    let password = "test_password_123";
    let config = AesGcmConfig::test_config();
    
    encrypt_single_file_with_config(&file1, &encrypted1, password, false, &config)
        .expect("Failed to encrypt file 1");
    encrypt_single_file_with_config(&file2, &encrypted2, password, false, &config)
        .expect("Failed to encrypt file 2");
    
    // Remove original files
    fs::remove_file(&file1).expect("Failed to remove original file 1");
    fs::remove_file(&file2).expect("Failed to remove original file 2");
    
    // Test multi-file decryption
    let encrypted_files = vec![encrypted1.clone(), encrypted2.clone()];
    let provider = DefaultConfigProvider::<AesGcmConfig>::test();
    let results = decrypt_multiple_files_with_provider(&encrypted_files, password, false, false, &provider, false)
        .expect("Multi-file decryption failed");
    
    // Verify results
    assert_eq!(results.successful.len(), 2);
    assert_eq!(results.failed.len(), 0);
    assert_eq!(results.total_files, 2);
    assert!(!results.has_failures());
    assert_eq!(results.success_rate(), 1.0);
    
    // Verify files were decrypted correctly
    let decrypted1 = temp_path.join("test1.txt");
    let decrypted2 = temp_path.join("test2.txt");
    
    assert!(decrypted1.exists(), "Decrypted file 1 should exist");
    assert!(decrypted2.exists(), "Decrypted file 2 should exist");
    
    let content1 = fs::read_to_string(&decrypted1).expect("Failed to read decrypted file 1");
    let content2 = fs::read_to_string(&decrypted2).expect("Failed to read decrypted file 2");
    
    assert_eq!(content1, "Content of file 1");
    assert_eq!(content2, "Content of file 2");
}

#[test]
fn test_decrypt_multiple_files_partial_failure() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let temp_path = temp_dir.path();
    
    // Create test files
    let file1 = temp_path.join("good.txt");
    let file2 = temp_path.join("corrupted.txt");
    fs::write(&file1, "Good content").expect("Failed to write test file 1");
    fs::write(&file2, "Bad content").expect("Failed to write test file 2");
    
    // Encrypt both files with different passwords
    let encrypted1 = temp_path.join("good.txt.shadow");
    let encrypted2 = temp_path.join("corrupted.txt.shadow");
    let password1 = "correct_password";
    let password2 = "different_password";
    let config = AesGcmConfig::test_config();
    
    encrypt_single_file_with_config(&file1, &encrypted1, password1, false, &config)
        .expect("Failed to encrypt good file");
    encrypt_single_file_with_config(&file2, &encrypted2, password2, false, &config)
        .expect("Failed to encrypt corrupted file");
    
    // Remove original files
    fs::remove_file(&file1).expect("Failed to remove original file 1");
    fs::remove_file(&file2).expect("Failed to remove original file 2");
    
    // Try to decrypt both with only one correct password
    let encrypted_files = vec![encrypted1.clone(), encrypted2.clone()];
    let provider = DefaultConfigProvider::<AesGcmConfig>::test();
    let results = decrypt_multiple_files_with_provider(&encrypted_files, password1, false, false, &provider, false)
        .expect("Multi-file decryption should not fail completely");
    
    // Verify partial success
    assert_eq!(results.successful.len(), 1);
    assert_eq!(results.failed.len(), 1);
    assert_eq!(results.total_files, 2);
    assert!(results.has_failures());
    assert_eq!(results.success_rate(), 0.5);
    
    // Verify the good file was decrypted
    let decrypted1 = temp_path.join("good.txt");
    assert!(decrypted1.exists(), "Good file should be decrypted");
    
    let content1 = fs::read_to_string(&decrypted1).expect("Failed to read decrypted good file");
    assert_eq!(content1, "Good content");
    
    // Verify the bad file was not decrypted
    let decrypted2 = temp_path.join("corrupted.txt");
    assert!(!decrypted2.exists(), "Corrupted file should not be decrypted");
}

#[test]
fn test_expand_glob_patterns_direct_files() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let temp_path = temp_dir.path();
    
    // Create test files
    let file1 = temp_path.join("test1.shadow");
    let file2 = temp_path.join("test2.shadow");
    fs::write(&file1, "dummy1").expect("Failed to write test file 1");
    fs::write(&file2, "dummy2").expect("Failed to write test file 2");
    
    // Test direct file paths
    let patterns = vec![
        file1.to_string_lossy().to_string(),
        file2.to_string_lossy().to_string(),
    ];
    
    let expanded = expand_glob_patterns(&patterns).expect("Failed to expand patterns");
    assert_eq!(expanded.len(), 2);
    assert!(expanded.contains(&file1));
    assert!(expanded.contains(&file2));
}

#[test]
fn test_expand_glob_patterns_wildcards() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let temp_path = temp_dir.path();
    
    // Create test files
    let file1 = temp_path.join("doc1.shadow");
    let file2 = temp_path.join("doc2.shadow");
    let file3 = temp_path.join("readme.txt");
    fs::write(&file1, "dummy1").expect("Failed to write test file 1");
    fs::write(&file2, "dummy2").expect("Failed to write test file 2");
    fs::write(&file3, "dummy3").expect("Failed to write test file 3");
    
    // Test wildcard pattern
    let pattern = format!("{}/*.shadow", temp_path.display());
    let patterns = vec![pattern];
    
    let expanded = expand_glob_patterns(&patterns).expect("Failed to expand glob pattern");
    assert_eq!(expanded.len(), 2);
    assert!(expanded.contains(&file1));
    assert!(expanded.contains(&file2));
    assert!(!expanded.contains(&file3)); // .txt file should not be included
}

#[test]
fn test_expand_glob_patterns_no_matches() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let temp_path = temp_dir.path();
    
    // Test pattern with no matches
    let pattern = format!("{}/*.nonexistent", temp_path.display());
    let patterns = vec![pattern];
    
    let result = expand_glob_patterns(&patterns);
    assert!(result.is_err(), "Should fail when no files match pattern");
}

#[test]
fn test_expand_glob_patterns_nonexistent_file() {
    let patterns = vec!["nonexistent_file.shadow".to_string()];
    
    let result = expand_glob_patterns(&patterns);
    assert!(result.is_err(), "Should fail for nonexistent file");
}

#[test]
fn test_multifile_results_structure() {
    use shadow_crypt::decryption::MultiFileResults;
    use std::time::Duration;
    
    // Test with all successful
    let results = MultiFileResults {
        successful: vec![PathBuf::from("file1"), PathBuf::from("file2")],
        failed: vec![],
        total_files: 2,
        total_time: Duration::from_secs(1),
    };
    
    assert_eq!(results.success_rate(), 1.0);
    assert!(!results.has_failures());
    
    // Test with mixed results
    let results = MultiFileResults {
        successful: vec![PathBuf::from("file1")],
        failed: vec![(PathBuf::from("file2"), "error".to_string())],
        total_files: 2,
        total_time: Duration::from_secs(2),
    };
    
    assert_eq!(results.success_rate(), 0.5);
    assert!(results.has_failures());
    
    // Test with all failed
    let results = MultiFileResults {
        successful: vec![],
        failed: vec![
            (PathBuf::from("file1"), "error1".to_string()),
            (PathBuf::from("file2"), "error2".to_string()),
        ],
        total_files: 2,
        total_time: Duration::from_secs(3),
    };
    
    assert_eq!(results.success_rate(), 0.0);
    assert!(results.has_failures());
}

#[test]
fn test_decrypt_multiple_files_with_source_removal() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let temp_path = temp_dir.path();
    
    // Create test files
    let file1 = temp_path.join("temp1.txt");
    let file2 = temp_path.join("temp2.txt");
    fs::write(&file1, "Temporary content 1").expect("Failed to write test file 1");
    fs::write(&file2, "Temporary content 2").expect("Failed to write test file 2");
    
    // Encrypt both files
    let encrypted1 = temp_path.join("temp1.txt.shadow");
    let encrypted2 = temp_path.join("temp2.txt.shadow");
    let password = "test_password_456";
    let config = AesGcmConfig::test_config();
    
    encrypt_single_file_with_config(&file1, &encrypted1, password, false, &config)
        .expect("Failed to encrypt file 1");
    encrypt_single_file_with_config(&file2, &encrypted2, password, false, &config)
        .expect("Failed to encrypt file 2");
    
    // Remove original files
    fs::remove_file(&file1).expect("Failed to remove original file 1");
    fs::remove_file(&file2).expect("Failed to remove original file 2");
    
    // Verify encrypted files exist
    assert!(encrypted1.exists(), "Encrypted file 1 should exist");
    assert!(encrypted2.exists(), "Encrypted file 2 should exist");
    
    // Note: Testing source removal in integration tests is complex because
    // it requires user confirmation. The functionality is tested in the
    // main application, but we test the decryption part here.
    
    // Test multi-file decryption without source removal
    let encrypted_files = vec![encrypted1.clone(), encrypted2.clone()];
    let provider = DefaultConfigProvider::<AesGcmConfig>::test();
    let results = decrypt_multiple_files_with_provider(&encrypted_files, password, false, false, &provider, false)
        .expect("Multi-file decryption failed");
    
    // Verify successful decryption
    assert_eq!(results.successful.len(), 2);
    assert_eq!(results.failed.len(), 0);
    
    // Verify both original and encrypted files exist (source not removed)
    assert!(encrypted1.exists(), "Encrypted file 1 should still exist");
    assert!(encrypted2.exists(), "Encrypted file 2 should still exist");
    
    let decrypted1 = temp_path.join("temp1.txt");
    let decrypted2 = temp_path.join("temp2.txt");
    assert!(decrypted1.exists(), "Decrypted file 1 should exist");
    assert!(decrypted2.exists(), "Decrypted file 2 should exist");
}