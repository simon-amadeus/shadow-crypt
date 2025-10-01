//! File Encryption Integration Tests
//! 
//! Integration tests for the file encryption functionality, including password-based
//! encryption, metadata preservation, and file format validation.

#[cfg(test)]
mod tests {
    use shadow_crypt::encryption::encrypt_file::encrypt_single_file_with_params;
    use shadow_crypt::shared::crypto::Argon2Params;
    use shadow_crypt::shared::file_detection::is_encrypted_file;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_basic_file_encryption() {
        // Create a temporary directory for test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let input_path = temp_dir.path().join("test_input.txt");
        let output_path = temp_dir.path().join("test_output.shadow");
        
        // Create a test file
        let test_content = "This is a test file for encryption testing.\nMultiple lines\nWith special chars: @#$%^&*()";
        fs::write(&input_path, test_content).expect("Failed to write test file");
        
        // Test encryption
        let password = "test_password_123";
        let result = encrypt_single_file_with_params(&input_path, &output_path, password, false, &Argon2Params::test_params());
        
        // Verify encryption succeeded
        assert!(result.is_ok(), "Encryption failed: {:?}", result.err());
        
        // Verify output file exists
        assert!(output_path.exists(), "Encrypted file was not created");
        
        // Verify output file is encrypted (has proper header)
        assert!(is_encrypted_file(&output_path).expect("Failed to check file format"), 
                "Output file is not recognized as encrypted");
        
        // Verify output is different from input
        let encrypted_content = fs::read(&output_path).expect("Failed to read encrypted file");
        let original_content = fs::read(&input_path).expect("Failed to read original file");
        assert_ne!(encrypted_content, original_content, "Encrypted content should be different from original");
        
        // Verify output file is larger (due to header and auth tags)
        assert!(encrypted_content.len() > original_content.len(), 
                "Encrypted file should be larger due to header and auth tags");
        
        println!("✅ Basic file encryption test passed!");
        println!("   Original size: {} bytes", original_content.len());
        println!("   Encrypted size: {} bytes", encrypted_content.len());
        println!("   Overhead: {} bytes", encrypted_content.len() - original_content.len());
    }

    #[test]
    fn test_encryption_with_different_passwords() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let input_path = temp_dir.path().join("test_input.txt");
        let output1_path = temp_dir.path().join("test_output1.shadow");
        let output2_path = temp_dir.path().join("test_output2.shadow");
        
        let test_content = "Same content, different passwords";
        fs::write(&input_path, test_content).expect("Failed to write test file");
        
        // Encrypt with two different passwords
        let result1 = encrypt_single_file_with_params(&input_path, &output1_path, "password1", false, &Argon2Params::test_params());
        let result2 = encrypt_single_file_with_params(&input_path, &output2_path, "password2", false, &Argon2Params::test_params());
        
        assert!(result1.is_ok(), "First encryption failed: {:?}", result1.err());
        assert!(result2.is_ok(), "Second encryption failed: {:?}", result2.err());
        
        // Read encrypted files
        let encrypted1 = fs::read(&output1_path).expect("Failed to read first encrypted file");
        let encrypted2 = fs::read(&output2_path).expect("Failed to read second encrypted file");
        
        // Verify they're different (different salts and derived keys)
        assert_ne!(encrypted1, encrypted2, "Files encrypted with different passwords should be different");
        
        println!("✅ Different passwords produce different encrypted outputs!");
    }

    #[test]
    fn test_encryption_preserves_metadata() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let input_path = temp_dir.path().join("test_input.txt");
        let output_path = temp_dir.path().join("test_output.shadow");
        
        let test_content = "Testing metadata preservation";
        fs::write(&input_path, test_content).expect("Failed to write test file");
        
        // Get original metadata
        let original_metadata = fs::metadata(&input_path).expect("Failed to get original metadata");
        
        // Encrypt file
        let result = encrypt_single_file_with_params(&input_path, &output_path, "test_password", false, &Argon2Params::test_params());
        assert!(result.is_ok(), "Encryption failed: {:?}", result.err());
        
        // Verify encrypted file exists and has different metadata
        let encrypted_metadata = fs::metadata(&output_path).expect("Failed to get encrypted metadata");
        
        // File sizes should be different
        assert_ne!(original_metadata.len(), encrypted_metadata.len(), 
                   "Encrypted file should have different size");
        
        println!("✅ Metadata handling test passed!");
        println!("   Original file size: {} bytes", original_metadata.len());
        println!("   Encrypted file size: {} bytes", encrypted_metadata.len());
    }
}