//! End-to-End Phase 5 Integration Test
//! 
//! This test validates the complete encryption/decryption workflow for Phase 5,
//! ensuring that all components work together correctly.

#[cfg(test)]
mod tests {
    use crypto::encryption::encrypt_single_file;
    use crypto::decryption::decrypt_single_file;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_phase5_end_to_end_workflow() {
        println!("🧪 Testing Phase 5: Basic File Decryption - End-to-End Workflow");
        
        // Create a temporary directory for test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let original_path = temp_dir.path().join("phase5_test.txt");
        let encrypted_path = temp_dir.path().join("phase5_test.txt.enc");
        let decrypted_path = temp_dir.path().join("phase5_test_decrypted.txt");
        
        // Create a comprehensive test file with various content types
        let test_content = "Phase 5 Test File\n\
                           =================\n\
                           \n\
                           This file tests the complete encryption/decryption workflow.\n\
                           \n\
                           Content includes:\n\
                           - Plain text with newlines\n\
                           - Special characters: !@#$%^&*()\n\
                           - Numbers: 123456789\n\
                           - Unicode: café, résumé, naïve\n\
                           - Emojis: 🔒🔐🗝️🔑\n\
                           \n\
                           End of test content.";
        
        fs::write(&original_path, test_content).expect("Failed to write test file");
        
        let password = "phase5_test_password_2024!";
        
        println!("📝 Created test file: {} bytes", test_content.len());
        
        // Step 1: Encrypt the file
        println!("🔒 Step 1: Encrypting file...");
        let encrypt_result = encrypt_single_file(&original_path, &encrypted_path, password, false);
        assert!(encrypt_result.is_ok(), "Encryption failed: {:?}", encrypt_result.err());
        assert!(encrypted_path.exists(), "Encrypted file was not created");
        
        let encrypted_size = fs::metadata(&encrypted_path).unwrap().len();
        println!("✅ Encryption successful! Encrypted size: {} bytes", encrypted_size);
        
        // Step 2: Verify encrypted file is different from original
        let original_bytes = fs::read(&original_path).expect("Failed to read original file");
        let encrypted_bytes = fs::read(&encrypted_path).expect("Failed to read encrypted file");
        assert_ne!(original_bytes, encrypted_bytes, "Encrypted content should be different from original");
        assert!(encrypted_bytes.len() > original_bytes.len(), "Encrypted file should be larger due to header and auth tags");
        
        // Step 3: Decrypt the file
        println!("🔓 Step 2: Decrypting file...");
        let decrypt_result = decrypt_single_file(&encrypted_path, &decrypted_path, password);
        assert!(decrypt_result.is_ok(), "Decryption failed: {:?}", decrypt_result.err());
        assert!(decrypted_path.exists(), "Decrypted file was not created");
        
        let decrypted_size = fs::metadata(&decrypted_path).unwrap().len();
        println!("✅ Decryption successful! Decrypted size: {} bytes", decrypted_size);
        
        // Step 4: Verify decrypted content matches original exactly
        let decrypted_bytes = fs::read(&decrypted_path).expect("Failed to read decrypted file");
        assert_eq!(original_bytes, decrypted_bytes, "Decrypted content does not match original");
        let original_len = original_bytes.len();
        let decrypted_len = decrypted_bytes.len();
        assert_eq!(original_len, decrypted_len, "File sizes should match exactly");
        
        // Step 5: Verify content as string to ensure no encoding issues
        let original_text = String::from_utf8(original_bytes).expect("Original content not valid UTF-8");
        let decrypted_text = String::from_utf8(decrypted_bytes).expect("Decrypted content not valid UTF-8");
        assert_eq!(original_text, decrypted_text, "Text content does not match");
        
        println!("🎉 Phase 5 End-to-End Test PASSED!");
        println!("   ✓ File encryption works correctly");
        println!("   ✓ File decryption works correctly");
        println!("   ✓ Content integrity is preserved");
        println!("   ✓ All special characters and Unicode handled correctly");
        println!("   ✓ File sizes are consistent");
        
        // Additional validation: Verify encryption overhead is reasonable
        let overhead = encrypted_bytes.len() - original_len;
        println!("📊 Encryption overhead: {} bytes", overhead);
        
        // Overhead should be reasonable (header + auth tags + padding)
        // Rough estimate: header (~200-300 bytes) + multiple auth tags (16 bytes each)
        assert!(overhead < 1000, "Encryption overhead seems too large: {} bytes", overhead);
        assert!(overhead > 100, "Encryption overhead seems too small: {} bytes", overhead);
    }

    #[test]
    fn test_phase5_authentication_failure() {
        println!("🧪 Testing Phase 5: Authentication Failure Detection");
        
        // Create a temporary directory for test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let original_path = temp_dir.path().join("auth_test.txt");
        let encrypted_path = temp_dir.path().join("auth_test.txt.enc");
        let decrypted_path = temp_dir.path().join("auth_test_decrypted.txt");
        
        let test_content = "Authentication test content";
        fs::write(&original_path, test_content).expect("Failed to write test file");
        
        let correct_password = "correct_password_123";
        let wrong_password = "wrong_password_456";
        
        // Encrypt with correct password
        let encrypt_result = encrypt_single_file(&original_path, &encrypted_path, correct_password, false);
        assert!(encrypt_result.is_ok(), "Encryption failed: {:?}", encrypt_result.err());
        
        // Try to decrypt with wrong password - should fail
        let decrypt_result = decrypt_single_file(&encrypted_path, &decrypted_path, wrong_password);
        assert!(decrypt_result.is_err(), "Decryption should fail with wrong password");
        
        match decrypt_result.err().unwrap() {
            crypto::shared::errors::CryptoError::CryptographicError(msg) => {
                println!("✅ Correctly rejected wrong password: {}", msg);
                assert!(msg.contains("decrypt") || msg.contains("authentication"), 
                        "Error message should indicate decryption/authentication failure");
            },
            other_error => {
                panic!("Expected CryptographicError, got: {:?}", other_error);
            }
        }
        
        // Verify no partial decrypted file was created
        assert!(!decrypted_path.exists(), "Decrypted file should not exist after failed decryption");
        
        println!("🎉 Authentication failure test PASSED!");
    }

    #[test]
    fn test_phase5_multiple_files() {
        println!("🧪 Testing Phase 5: Multiple Files with Different Passwords");
        
        // Create a temporary directory for test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        
        let files_and_passwords = vec![
            ("file1.txt", "password1", "Content of file 1"),
            ("file2.txt", "password2", "Different content for file 2"),
            ("file3.txt", "password3", "Yet another content for file 3"),
        ];
        
        for (filename, password, content) in &files_and_passwords {
            let original_path = temp_dir.path().join(filename);
            let encrypted_path = temp_dir.path().join(format!("{}.enc", filename));
            let decrypted_path = temp_dir.path().join(format!("{}.dec", filename));
            
            // Write original file
            fs::write(&original_path, content).expect("Failed to write test file");
            
            // Encrypt
            let encrypt_result = encrypt_single_file(&original_path, &encrypted_path, password, false);
            assert!(encrypt_result.is_ok(), "Encryption failed for {}: {:?}", filename, encrypt_result.err());
            
            // Decrypt
            let decrypt_result = decrypt_single_file(&encrypted_path, &decrypted_path, password);
            assert!(decrypt_result.is_ok(), "Decryption failed for {}: {:?}", filename, decrypt_result.err());
            
            // Verify content
            let decrypted_content = fs::read_to_string(&decrypted_path).expect("Failed to read decrypted file");
            assert_eq!(*content, decrypted_content, "Content mismatch for {}", filename);
            
            println!("✅ File {} processed successfully", filename);
        }
        
        println!("🎉 Multiple files test PASSED!");
    }
}