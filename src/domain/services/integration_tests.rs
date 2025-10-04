#[cfg(test)]
mod domain_services_integration_tests {
    use std::path::PathBuf;
    use tempfile::tempdir;
    use crate::domain::services::{EncryptionService, DecryptionService, ListingService, EncryptionOptions, DecryptionOptions};
    use crate::infrastructure::crypto::factory::Algorithm;
    use crate::domain::entities::AlgorithmId;

    #[test]
    fn test_encryption_decryption_roundtrip() {
        // Setup test environment
        let temp_dir = tempdir().unwrap();
        let input_file = temp_dir.path().join("test.txt");
        let encrypted_file = temp_dir.path().join("test.txt.shadow");
        let decrypted_file = temp_dir.path().join("test_decrypted.txt");
        
        let test_content = b"Hello, World! This is a test file for encryption.";
        let password = "test_password_123";
        
        // Write test content
        std::fs::write(&input_file, test_content).unwrap();
        
        // Test encryption
        let mut encryption_service = EncryptionService::new()
            .with_progress_reporting(false);
        
        let algorithm = Algorithm::from_id(AlgorithmId::XChaCha20Poly1305);
        let encrypt_options = EncryptionOptions {
            obfuscate_filename: false,
            force_overwrite: true,
            remove_source: false,
            check_duplicates: false,
        };
        
        let encrypt_result = encryption_service.encrypt_file(
            &input_file,
            &encrypted_file,
            &algorithm,
            password,
            encrypt_options,
        ).unwrap();
        
        assert_eq!(encrypt_result.input_path, input_file);
        assert_eq!(encrypt_result.output_path, encrypted_file);
        assert_eq!(encrypt_result.algorithm, AlgorithmId::XChaCha20Poly1305);
        assert!(encrypted_file.exists());
        
        // Test decryption
        let mut decryption_service = DecryptionService::new()
            .with_progress_reporting(false);
        
        let decrypt_options = DecryptionOptions {
            force_overwrite: true,
            remove_source: false,
            verify_integrity: true,
        };
        
        let decrypt_result = decryption_service.decrypt_file(
            &encrypted_file,
            Some(&decrypted_file),
            password,
            decrypt_options,
        ).unwrap();
        
        assert_eq!(decrypt_result.input_path, encrypted_file);
        assert_eq!(decrypt_result.output_path, decrypted_file);
        assert_eq!(decrypt_result.algorithm, AlgorithmId::XChaCha20Poly1305);
        assert!(decrypted_file.exists());
        
        // Verify content integrity
        let decrypted_content = std::fs::read(&decrypted_file).unwrap();
        assert_eq!(decrypted_content, test_content);
    }

    #[test]
    fn test_listing_service_directory_scan() {
        // Setup test environment with multiple encrypted files
        let temp_dir = tempdir().unwrap();
        let password = "test_password_123";
        
        // Create and encrypt multiple test files
        let mut encryption_service = EncryptionService::new();
        let algorithm = Algorithm::from_id(AlgorithmId::XChaCha20Poly1305);
        let encrypt_options = EncryptionOptions {
            obfuscate_filename: false,
            force_overwrite: true,
            remove_source: false,
            check_duplicates: false,
        };
        
        for i in 1..=3 {
            let input_file = temp_dir.path().join(format!("test{}.txt", i));
            let encrypted_file = temp_dir.path().join(format!("test{}.txt.shadow", i));
            let content = format!("Test content for file {}", i);
            
            std::fs::write(&input_file, content.as_bytes()).unwrap();
            
            encryption_service.encrypt_file(
                &input_file,
                &encrypted_file,
                &algorithm,
                password,
                encrypt_options.clone(),
            ).unwrap();
        }
        
        // Test listing service
        let listing_service = ListingService::new();
        let directory_listing = listing_service.scan_directory(
            temp_dir.path(),
            password,
        ).unwrap();
        
        assert_eq!(directory_listing.directory, temp_dir.path());
        assert_eq!(directory_listing.files.len(), 3);
        
        // Verify each file was detected correctly
        for file_info in &directory_listing.files {
            assert!(file_info.password_valid);
            assert_eq!(file_info.algorithm, AlgorithmId::XChaCha20Poly1305);
            assert_eq!(file_info.version, 1);
            assert!(file_info.size > 0);
            assert!(file_info.path.to_string_lossy().contains("shadow"));
        }
    }

    #[test]
    fn test_batch_encryption_and_listing() {
        // Setup test environment
        let temp_dir = tempdir().unwrap();
        let password = "batch_test_password";
        
        // Create multiple test files
        let file_pairs: Vec<(PathBuf, PathBuf)> = (1..=5)
            .map(|i| {
                let input_file = temp_dir.path().join(format!("batch_test{}.txt", i));
                let encrypted_file = temp_dir.path().join(format!("batch_test{}.shadow", i));
                let content = format!("Batch test content for file number {}", i);
                std::fs::write(&input_file, content.as_bytes()).unwrap();
                (input_file, encrypted_file)
            })
            .collect();
        
        // Test batch encryption
        let mut encryption_service = EncryptionService::new();
        let algorithm = Algorithm::from_id(AlgorithmId::XChaCha20Poly1305);
        let encrypt_options = EncryptionOptions {
            obfuscate_filename: false,
            force_overwrite: true,
            remove_source: false,
            check_duplicates: false,
        };
        
        let batch_result = encryption_service.encrypt_multiple_files(
            file_pairs,
            &algorithm,
            password,
            encrypt_options,
        ).unwrap();
        
        assert_eq!(batch_result.successful.len(), 5);
        assert_eq!(batch_result.failed.len(), 0);
        
        // Test listing all encrypted files
        let listing_service = ListingService::new();
        let directory_listing = listing_service.scan_directory(
            temp_dir.path(),
            password,
        ).unwrap();
        
        assert_eq!(directory_listing.files.len(), 5);
        
        // Verify all files are properly encrypted and detectable
        for file_info in &directory_listing.files {
            assert!(file_info.password_valid);
            assert_eq!(file_info.algorithm, AlgorithmId::XChaCha20Poly1305);
            assert!(file_info.path.to_string_lossy().contains("shadow"));
        }
    }
}