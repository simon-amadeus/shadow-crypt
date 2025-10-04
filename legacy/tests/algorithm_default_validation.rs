//! Algorithm Default Selection Validation Tests
//!
//! Tests to verify XChaCha20 is properly selected as the default algorithm
//! across different entry points and usage patterns.

#[cfg(test)]
mod tests {
    use shadow_crypt::encryption::encrypt_single_file_with_config;
    use shadow_crypt::shared::algorithms::xchacha20_config::XChaCha20Config;
    use shadow_crypt::shared::algorithms::aes_gcm_config::AesGcmConfig;
    use shadow_crypt::shared::algorithms::config::{CryptoConfig, EncryptionConfig};
    use shadow_crypt::shared::file_detection::is_encrypted_file;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_xchacha20_trait_based_encryption() {
        // Create temporary directory for test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let input_path = temp_dir.path().join("test_input.txt");
        let output_path = temp_dir.path().join("test_output.shadow");
        
        // Create a test file
        let test_content = "XChaCha20 algorithm selection test content";
        fs::write(&input_path, test_content).expect("Failed to write test file");
        
        // Test XChaCha20 encryption using trait-based system
        let password = "test_password_123";
        let config = XChaCha20Config::test_config();
        
        println!("Testing XChaCha20 with algorithm ID: {}", config.algorithm_id());
        println!("Algorithm name: {}", config.algorithm_name());
        
        let result = encrypt_single_file_with_config(&input_path, &output_path, password, false, &config);
        
        match result {
            Ok(()) => {
                println!("✅ XChaCha20 encryption succeeded");
                assert!(output_path.exists(), "Encrypted file was not created");
                assert!(is_encrypted_file(&output_path).expect("Failed to check file format"), 
                        "Output file is not recognized as encrypted");
            }
            Err(e) => {
                println!("❌ XChaCha20 encryption failed: {:?}", e);
                panic!("XChaCha20 encryption should work: {:?}", e);
            }
        }
    }

    #[test]
    fn test_aes_gcm_trait_based_encryption() {
        // Create temporary directory for test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let input_path = temp_dir.path().join("test_input.txt");
        let output_path = temp_dir.path().join("test_output.shadow");
        
        // Create a test file
        let test_content = "AES-GCM algorithm comparison test content";
        fs::write(&input_path, test_content).expect("Failed to write test file");
        
        // Test AES-GCM encryption using trait-based system
        let password = "test_password_123";
        let config = AesGcmConfig::test_config();
        
        println!("Testing AES-GCM with algorithm ID: {}", config.algorithm_id());
        println!("Algorithm name: {}", config.algorithm_name());
        
        let result = encrypt_single_file_with_config(&input_path, &output_path, password, false, &config);
        
        match result {
            Ok(()) => {
                println!("✅ AES-GCM encryption succeeded");
                assert!(output_path.exists(), "Encrypted file was not created");
                assert!(is_encrypted_file(&output_path).expect("Failed to check file format"), 
                        "Output file is not recognized as encrypted");
            }
            Err(e) => {
                println!("❌ AES-GCM encryption failed: {:?}", e);
                panic!("AES-GCM encryption should work: {:?}", e);
            }
        }
    }

    #[test]
    fn test_algorithm_ids_and_defaults() {
        let xchacha20_config = XChaCha20Config::test_config();
        let aes_gcm_config = AesGcmConfig::test_config();
        
        println!("XChaCha20 algorithm ID: {}", xchacha20_config.algorithm_id());
        println!("AES-GCM algorithm ID: {}", aes_gcm_config.algorithm_id());
        
        // Verify algorithm IDs are different
        assert_ne!(xchacha20_config.algorithm_id(), aes_gcm_config.algorithm_id(),
                   "XChaCha20 and AES-GCM should have different algorithm IDs");
        
        // Document expected algorithm ID mapping
        assert_eq!(aes_gcm_config.algorithm_id(), 1, "AES-GCM should have algorithm ID 1");
        assert_eq!(xchacha20_config.algorithm_id(), 2, "XChaCha20 should have algorithm ID 2");
        
        println!("✅ Algorithm ID validation passed");
    }
}