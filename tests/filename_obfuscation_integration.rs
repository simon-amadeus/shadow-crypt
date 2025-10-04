//! # Filename Obfuscation Integration Test
//! 
//! Tests end-to-end filename obfuscation functionality across the encryption and decryption workflow.

use shadow_crypt::domain::services::{EncryptionService, DecryptionService, EncryptionOptions, DecryptionOptions};
use shadow_crypt::domain::utilities::filename_obfuscation::FilenameObfuscator;
use shadow_crypt::infrastructure::crypto::factory::Algorithm;
use tempfile::NamedTempFile;
use std::fs;

#[test]
fn test_filename_obfuscation_roundtrip() {
    // Phase 1: Setup test data
    let temp_file = NamedTempFile::new().unwrap();
    let original_path = temp_file.path();
    let test_content = b"This is test content for filename obfuscation";
    fs::write(original_path, test_content).unwrap();
    
    let password = "test_password_123";
    let algorithm = Algorithm::xchacha20_poly1305();
    
    // Phase 2: Create obfuscated output path
    let (obfuscated_output_path, obfuscated_info) = FilenameObfuscator::create_obfuscated_output_path(
        original_path, 
        false
    ).unwrap();
    
    // Verify obfuscated filename is different from original
    assert_ne!(
        obfuscated_output_path.file_name().unwrap().to_str().unwrap(),
        original_path.file_name().unwrap().to_str().unwrap()
    );
    assert_eq!(obfuscated_info.original_name, original_path.file_name().unwrap().to_str().unwrap());
    
    // Phase 3: Encrypt with obfuscation enabled
    let mut encryption_service = EncryptionService::new().with_progress_reporting(false);
    let encryption_options = EncryptionOptions {
        obfuscate_filename: true,
        force_overwrite: false,
        remove_source: false,
        check_duplicates: false,
    };
    
    let encryption_result = encryption_service.encrypt_file_with_obfuscation(
        original_path,
        &algorithm,
        password,
        encryption_options
    ).unwrap();
    
    // Verify encrypted file exists with obfuscated name
    assert!(encryption_result.output_path.exists());
    assert_ne!(
        encryption_result.output_path.file_name().unwrap().to_str().unwrap(),
        original_path.file_name().unwrap().to_str().unwrap()
    );
    
    // Phase 4: Decrypt with automatic filename restoration
    let mut decryption_service = DecryptionService::new().with_progress_reporting(false);
    let decryption_options = DecryptionOptions {
        force_overwrite: true,
        remove_source: false,
        verify_integrity: false,
    };
    
    let decryption_result = decryption_service.decrypt_file(
        &encryption_result.output_path,
        None, // Auto-detect original filename
        password,
        decryption_options
    ).unwrap();
    
    // Phase 5: Verify filename restoration
    assert_eq!(
        decryption_result.original_filename.as_ref().unwrap(),
        original_path.file_name().unwrap().to_str().unwrap()
    );
    
    // Verify restored filename matches original
    assert_eq!(
        decryption_result.output_path.file_name().unwrap().to_str().unwrap(),
        original_path.file_name().unwrap().to_str().unwrap()
    );
    
    // Phase 6: Verify content integrity
    let restored_content = fs::read(&decryption_result.output_path).unwrap();
    assert_eq!(restored_content, test_content);
    
    // Cleanup
    let _ = fs::remove_file(&encryption_result.output_path);
    let _ = fs::remove_file(&decryption_result.output_path);
}

#[test]
fn test_filename_obfuscation_disabled() {
    // Test that when obfuscation is disabled, original filename is preserved
    let temp_file = NamedTempFile::new().unwrap();
    let original_path = temp_file.path();
    let test_content = b"Test content without obfuscation";
    fs::write(original_path, test_content).unwrap();
    
    let password = "test_password_456";
    let algorithm = Algorithm::aes256_gcm();
    
    let mut encryption_service = EncryptionService::new().with_progress_reporting(false);
    let encryption_options = EncryptionOptions {
        obfuscate_filename: false,
        force_overwrite: false,
        remove_source: false,
        check_duplicates: false,
    };
    
    let encryption_result = encryption_service.encrypt_file_with_obfuscation(
        original_path,
        &algorithm,
        password,
        encryption_options
    ).unwrap();
    
    // With obfuscation disabled, output should be original filename + .shadow extension
    let expected_filename = format!("{}.shadow", original_path.file_name().unwrap().to_str().unwrap());
    assert_eq!(
        encryption_result.output_path.file_name().unwrap().to_str().unwrap(),
        expected_filename
    );
    
    // Cleanup
    let _ = fs::remove_file(&encryption_result.output_path);
}

#[test]
fn test_filename_obfuscation_security_validation() {
    // Test that malicious filenames are caught during restoration
    let temp_file = NamedTempFile::new().unwrap();
    let original_path = temp_file.path();
    
    // Test path separator rejection
    let result = FilenameObfuscator::restore_original_filename(original_path, "../malicious.txt");
    assert!(result.is_err());
    
    let result = FilenameObfuscator::restore_original_filename(original_path, "sub\\malicious.txt");
    assert!(result.is_err());
    
    // Test valid filename works
    let result = FilenameObfuscator::restore_original_filename(original_path, "safe_filename.txt");
    assert!(result.is_ok());
}

#[test]
fn test_filename_obfuscation_cross_platform_safety() {
    // Test Windows reserved names
    let reserved_names = ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"];
    
    for reserved_name in &reserved_names {
        let result = FilenameObfuscator::validate_filename_safety(reserved_name);
        assert!(result.is_err(), "Reserved name {} should be rejected", reserved_name);
        
        let with_extension = format!("{}.txt", reserved_name);
        let result = FilenameObfuscator::validate_filename_safety(&with_extension);
        assert!(result.is_err(), "Reserved name with extension {} should be rejected", with_extension);
    }
    
    // Test problematic characters
    let problematic_chars = ['<', '>', ':', '"', '|', '?', '*'];
    for ch in &problematic_chars {
        let filename = format!("file{}name.txt", ch);
        let result = FilenameObfuscator::validate_filename_safety(&filename);
        assert!(result.is_err(), "Filename with character {} should be rejected", ch);
    }
    
    // Test safe filenames
    let safe_filenames = [
        "document.txt",
        "my-file_123.pdf",
        "data.json",
        "archive.tar.gz",
        "test file with spaces.doc",
    ];
    
    for safe_name in &safe_filenames {
        let result = FilenameObfuscator::validate_filename_safety(safe_name);
        assert!(result.is_ok(), "Safe filename {} should be accepted", safe_name);
    }
}

#[test]
fn test_obfuscated_filename_uniqueness() {
    // Verify that multiple calls generate unique obfuscated names
    let temp_file = NamedTempFile::new().unwrap();
    let original_path = temp_file.path();
    
    let mut obfuscated_names = std::collections::HashSet::new();
    
    // Generate 100 obfuscated filenames and ensure they're all unique
    for _ in 0..100 {
        let result = FilenameObfuscator::obfuscate_filename(original_path, false).unwrap();
        let was_inserted = obfuscated_names.insert(result.obfuscated_name.clone());
        assert!(was_inserted, "Duplicate obfuscated filename generated: {}", result.obfuscated_name);
    }
    
    assert_eq!(obfuscated_names.len(), 100);
}

#[test] 
fn test_filename_obfuscation_with_extension_preservation() {
    let temp_file = NamedTempFile::new().unwrap();
    let original_path = temp_file.path();
    let test_content = b"Test content with extension preservation";
    fs::write(original_path, test_content).unwrap();
    
    // Test with extension preservation enabled
    let (obfuscated_path, obfuscated_info) = FilenameObfuscator::create_obfuscated_output_path(
        original_path, 
        true // preserve extension
    ).unwrap();
    
    // Original filename likely has a temp extension - verify obfuscated version preserves it and adds .shadow
    if let Some(original_ext) = original_path.extension() {
        let expected_ending = format!(".{}.shadow", original_ext.to_str().unwrap());
        assert!(obfuscated_path.to_str().unwrap().ends_with(&expected_ending));
        assert_eq!(obfuscated_info.extension, original_path.extension().and_then(|ext| ext.to_str()).map(|s| s.to_string()));
    }
    
    // Test with extension preservation disabled
    let (obfuscated_path_no_ext, obfuscated_info_no_ext) = FilenameObfuscator::create_obfuscated_output_path(
        original_path, 
        false // don't preserve extension
    ).unwrap();
    
    assert!(obfuscated_path_no_ext.to_str().unwrap().ends_with(".shadow"));
    assert_eq!(obfuscated_info_no_ext.extension, None);
}