//! File Decryption Integration Tests
//! 
//! Integration tests for the file decryption functionality, including roundtrip
//! encryption/decryption, authentication verification, and metadata restoration.

#[cfg(test)]
mod tests {
    use crypto::encryption::encrypt_single_file;
    use crypto::decryption::decrypt_single_file;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_basic_file_decryption() {
        // Create a temporary directory for test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let original_path = temp_dir.path().join("original.txt");
        let encrypted_path = temp_dir.path().join("encrypted.enc");
        let decrypted_path = temp_dir.path().join("decrypted.txt");
        
        // Create a test file
        let test_content = "This is a test file for decryption testing.\nMultiple lines\nWith special chars: @#$%^&*()";
        fs::write(&original_path, test_content).expect("Failed to write test file");
        
        let password = "test_password_123";
        
        // Encrypt the file
        let encrypt_result = encrypt_single_file(&original_path, &encrypted_path, password, false);
        assert!(encrypt_result.is_ok(), "Encryption failed: {:?}", encrypt_result.err());
        assert!(encrypted_path.exists(), "Encrypted file was not created");
        
        // Decrypt the file
        let decrypt_result = decrypt_single_file(&encrypted_path, &decrypted_path, password);
        assert!(decrypt_result.is_ok(), "Decryption failed: {:?}", decrypt_result.err());
        assert!(decrypted_path.exists(), "Decrypted file was not created");
        
        // Verify content matches exactly
        let original_content = fs::read(&original_path).expect("Failed to read original file");
        let decrypted_content = fs::read(&decrypted_path).expect("Failed to read decrypted file");
        assert_eq!(original_content, decrypted_content, "Decrypted content does not match original");
        
        println!("✅ Basic file decryption test passed!");
        println!("   Original size: {} bytes", original_content.len());
        println!("   Content matches: {}", original_content == decrypted_content);
    }

    #[test]
    fn test_decryption_wrong_password() {
        // Create a temporary directory for test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let original_path = temp_dir.path().join("original.txt");
        let encrypted_path = temp_dir.path().join("encrypted.enc");
        let decrypted_path = temp_dir.path().join("decrypted.txt");
        
        // Create a test file
        let test_content = "Secret content that should not be decryptable with wrong password";
        fs::write(&original_path, test_content).expect("Failed to write test file");
        
        let correct_password = "correct_password_123";
        let wrong_password = "wrong_password_456";
        
        // Encrypt the file
        let encrypt_result = encrypt_single_file(&original_path, &encrypted_path, correct_password, false);
        assert!(encrypt_result.is_ok(), "Encryption failed: {:?}", encrypt_result.err());
        
        // Try to decrypt with wrong password - should fail
        let decrypt_result = decrypt_single_file(&encrypted_path, &decrypted_path, wrong_password);
        assert!(decrypt_result.is_err(), "Decryption should fail with wrong password");
        
        // Verify the error is cryptographic (authentication failure)
        match decrypt_result.err().unwrap() {
            crypto::shared::errors::CryptoError::CryptographicError(_) => {
                println!("✅ Correctly rejected wrong password with cryptographic error");
            },
            other_error => {
                panic!("Expected CryptographicError, got: {:?}", other_error);
            }
        }
        
        // Verify no decrypted file was created
        assert!(!decrypted_path.exists(), "Decrypted file should not exist after failed decryption");
    }

    #[test]
    fn test_decryption_corrupted_file() {
        // Create a temporary directory for test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let original_path = temp_dir.path().join("original.txt");
        let encrypted_path = temp_dir.path().join("encrypted.enc");
        let corrupted_path = temp_dir.path().join("corrupted.enc");
        let decrypted_path = temp_dir.path().join("decrypted.txt");
        
        // Create a test file
        let test_content = "Content to test corruption detection";
        fs::write(&original_path, test_content).expect("Failed to write test file");
        
        let password = "test_password_123";
        
        // Encrypt the file
        let encrypt_result = encrypt_single_file(&original_path, &encrypted_path, password, false);
        assert!(encrypt_result.is_ok(), "Encryption failed: {:?}", encrypt_result.err());
        
        // Corrupt the encrypted file by modifying some bytes
        let mut encrypted_data = fs::read(&encrypted_path).expect("Failed to read encrypted file");
        // Corrupt the last few bytes (likely part of the content)
        let data_len = encrypted_data.len();
        if data_len > 50 {
            encrypted_data[data_len - 10] ^= 0xFF;
            encrypted_data[data_len - 5] ^= 0xFF;
        }
        fs::write(&corrupted_path, &encrypted_data).expect("Failed to write corrupted file");
        
        // Try to decrypt corrupted file - should fail
        let decrypt_result = decrypt_single_file(&corrupted_path, &decrypted_path, password);
        assert!(decrypt_result.is_err(), "Decryption should fail with corrupted file");
        
        // Verify the error is cryptographic (authentication failure)
        match decrypt_result.err().unwrap() {
            crypto::shared::errors::CryptoError::CryptographicError(_) => {
                println!("✅ Correctly detected file corruption with cryptographic error");
            },
            other_error => {
                panic!("Expected CryptographicError, got: {:?}", other_error);
            }
        }
        
        // Verify no decrypted file was created
        assert!(!decrypted_path.exists(), "Decrypted file should not exist after failed decryption");
    }

    #[test]
    fn test_decryption_empty_file() {
        // Create a temporary directory for test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let original_path = temp_dir.path().join("empty.txt");
        let encrypted_path = temp_dir.path().join("empty.enc");
        let decrypted_path = temp_dir.path().join("empty_decrypted.txt");
        
        // Create an empty test file
        fs::write(&original_path, "").expect("Failed to write empty test file");
        
        let password = "test_password_123";
        
        // Encrypt the empty file
        let encrypt_result = encrypt_single_file(&original_path, &encrypted_path, password, false);
        assert!(encrypt_result.is_ok(), "Encryption of empty file failed: {:?}", encrypt_result.err());
        
        // Decrypt the empty file
        let decrypt_result = decrypt_single_file(&encrypted_path, &decrypted_path, password);
        assert!(decrypt_result.is_ok(), "Decryption of empty file failed: {:?}", decrypt_result.err());
        
        // Verify the decrypted file is also empty
        let decrypted_content = fs::read(&decrypted_path).expect("Failed to read decrypted empty file");
        assert_eq!(decrypted_content.len(), 0, "Decrypted empty file should be empty");
        
        println!("✅ Empty file decryption test passed!");
    }

    #[test]
    fn test_decryption_large_file() {
        // Create a temporary directory for test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let original_path = temp_dir.path().join("large.txt");
        let encrypted_path = temp_dir.path().join("large.enc");
        let decrypted_path = temp_dir.path().join("large_decrypted.txt");
        
        // Create a larger test file (1MB)
        let chunk = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(100);
        let large_content = chunk.repeat(300); // Approximately 1MB
        fs::write(&original_path, &large_content).expect("Failed to write large test file");
        
        let password = "test_password_123";
        
        // Encrypt the large file
        let encrypt_result = encrypt_single_file(&original_path, &encrypted_path, password, false);
        assert!(encrypt_result.is_ok(), "Encryption of large file failed: {:?}", encrypt_result.err());
        
        // Decrypt the large file
        let decrypt_result = decrypt_single_file(&encrypted_path, &decrypted_path, password);
        assert!(decrypt_result.is_ok(), "Decryption of large file failed: {:?}", decrypt_result.err());
        
        // Verify content matches exactly
        let original_content = fs::read(&original_path).expect("Failed to read original large file");
        let decrypted_content = fs::read(&decrypted_path).expect("Failed to read decrypted large file");
        assert_eq!(original_content, decrypted_content, "Decrypted large file content does not match original");
        
        println!("✅ Large file decryption test passed!");
        println!("   File size: {} bytes", original_content.len());
    }

    #[test]
    fn test_roundtrip_with_special_characters() {
        // Create a temporary directory for test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let original_path = temp_dir.path().join("special_chars.txt");
        let encrypted_path = temp_dir.path().join("special_chars.enc");
        let decrypted_path = temp_dir.path().join("special_chars_decrypted.txt");
        
        // Create a test file with various special characters and Unicode
        let mut test_content = String::from("Special characters: !@#$%^&*()_+-=[]{}|;':\",./<>?\n");
        test_content.push_str("Unicode: 🔒🔐🗝️🔑\n");
        test_content.push_str("Non-ASCII: café, résumé, naïve\n");
        
        // Add some binary data using bytes
        let mut content_bytes = test_content.into_bytes();
        content_bytes.extend_from_slice(b"Binary-like: ");
        content_bytes.extend_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x7F, 0x7E, 0x7D]);
        content_bytes.extend_from_slice(b"\n");
        content_bytes.extend_from_slice("Emoji: 😀😃😄😁🤣😂".as_bytes());
        
        fs::write(&original_path, &content_bytes).expect("Failed to write special chars test file");
        
        let password = "special_password_🔒🔑";
        
        // Encrypt the file
        let encrypt_result = encrypt_single_file(&original_path, &encrypted_path, password, false);
        assert!(encrypt_result.is_ok(), "Encryption of special chars file failed: {:?}", encrypt_result.err());
        
        // Decrypt the file
        let decrypt_result = decrypt_single_file(&encrypted_path, &decrypted_path, password);
        assert!(decrypt_result.is_ok(), "Decryption of special chars file failed: {:?}", decrypt_result.err());
        
        // Verify content matches exactly
        let original_content = fs::read(&original_path).expect("Failed to read original special chars file");
        let decrypted_content = fs::read(&decrypted_path).expect("Failed to read decrypted special chars file");
        assert_eq!(original_content, decrypted_content, "Decrypted special chars content does not match original");
        
        println!("✅ Special characters decryption test passed!");
    }
}