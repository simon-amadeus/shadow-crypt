//! File Decryption Integration Tests
//! 
//! Integration tests for the file decryption functionality, including roundtrip
//! encryption/decryption, authentication verification, and metadata restoration.

#[cfg(test)]
mod tests {
    use shadow_crypt::encryption::encrypt_file::encrypt_single_file_with_params;
    use shadow_crypt::shared::crypto::Argon2Params;
    use shadow_crypt::decryption::decrypt_file::decrypt_single_file_with_params;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_basic_file_decryption() {
        // Create a temporary directory for test files
        let temp_dir = tempdir().unwrap();
        let original_path = temp_dir.path().join("test_file.txt");
        let encrypted_path = temp_dir.path().join("test_file.txt.shadow");
        let decrypted_path = temp_dir.path().join("decrypted_file.txt");
        
        // Create original file
        fs::write(&original_path, "Hello, this is a test file for decryption!").unwrap();
        
        let password = "test_password_123";
        
        // Encrypt the file
        let params = Argon2Params::test_params();
        let encrypt_result = encrypt_single_file_with_params(&original_path, &encrypted_path, password, false, &params);
        assert!(encrypt_result.is_ok(), "Encryption failed: {:?}", encrypt_result.err());
        assert!(encrypted_path.exists(), "Encrypted file was not created");
        
        // Decrypt the file
        let decrypt_result = decrypt_single_file_with_params(&encrypted_path, &decrypted_path, password, &params);
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
        let encrypted_path = temp_dir.path().join("encrypted.shadow");
        let decrypted_path = temp_dir.path().join("decrypted.txt");
        
        // Create a test file
        let test_content = "Secret content that should not be decryptable with wrong password";
        fs::write(&original_path, test_content).expect("Failed to write test file");
        
        let correct_password = "correct_password_123";
        let wrong_password = "wrong_password_456";
        
        // Encrypt the file
        let params = Argon2Params::test_params();
        let encrypt_result = encrypt_single_file_with_params(&original_path, &encrypted_path, correct_password, false, &params);
        assert!(encrypt_result.is_ok(), "Encryption failed: {:?}", encrypt_result.err());
        
        // Try to decrypt with wrong password - should fail
        let decrypt_result = decrypt_single_file_with_params(&encrypted_path, &decrypted_path, wrong_password, &params);
        assert!(decrypt_result.is_err(), "Decryption should fail with wrong password");
        
        // Verify the error is cryptographic (authentication failure)
        match decrypt_result.err().unwrap() {
            shadow_crypt::shared::errors::CryptoError::CryptographicError(_) => {
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
        let encrypted_path = temp_dir.path().join("encrypted.shadow");
        let corrupted_path = temp_dir.path().join("corrupted.shadow");
        let decrypted_path = temp_dir.path().join("decrypted.txt");
        
        // Create a test file
        let test_content = "Content to test corruption detection";
        fs::write(&original_path, test_content).expect("Failed to write test file");
        
        let password = "test_password_123";
        
        // Encrypt the file
        let params = Argon2Params::test_params();
        let encrypt_result = encrypt_single_file_with_params(&original_path, &encrypted_path, password, false, &params);
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
        let decrypt_result = decrypt_single_file_with_params(&corrupted_path, &decrypted_path, password, &params);
        assert!(decrypt_result.is_err(), "Decryption should fail with corrupted file");
        
        // Verify the error is cryptographic (authentication failure)
        match decrypt_result.err().unwrap() {
            shadow_crypt::shared::errors::CryptoError::CryptographicError(_) => {
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
        let encrypted_path = temp_dir.path().join("empty.shadow");
        let decrypted_path = temp_dir.path().join("empty_decrypted.txt");
        
        // Create an empty test file
        fs::write(&original_path, "").expect("Failed to write empty test file");
        
        let password = "test_password_123";
        
        // Encrypt the empty file
        let params = Argon2Params::test_params();
        let encrypt_result = encrypt_single_file_with_params(&original_path, &encrypted_path, password, false, &params);
        assert!(encrypt_result.is_ok(), "Encryption of empty file failed: {:?}", encrypt_result.err());
        
        // Decrypt the empty file
        let decrypt_result = decrypt_single_file_with_params(&encrypted_path, &decrypted_path, password, &params);
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
        let encrypted_path = temp_dir.path().join("large.shadow");
        let decrypted_path = temp_dir.path().join("large_decrypted.txt");
        
        // Create a larger test file (1MB)
        let chunk = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(100);
        let large_content = chunk.repeat(300); // Approximately 1MB
        fs::write(&original_path, &large_content).expect("Failed to write large test file");
        
        let password = "test_password_123";
        
        // Encrypt the large file
        let params = Argon2Params::test_params();
        let encrypt_result = encrypt_single_file_with_params(&original_path, &encrypted_path, password, false, &params);
        assert!(encrypt_result.is_ok(), "Encryption of large file failed: {:?}", encrypt_result.err());
        
        // Decrypt the large file
        let decrypt_result = decrypt_single_file_with_params(&encrypted_path, &decrypted_path, password, &params);
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
        let encrypted_path = temp_dir.path().join("special_chars.shadow");
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
        let params = Argon2Params::test_params();
        let encrypt_result = encrypt_single_file_with_params(&original_path, &encrypted_path, password, false, &params);
        assert!(encrypt_result.is_ok(), "Encryption of special chars file failed: {:?}", encrypt_result.err());
        
        // Decrypt the file
        let decrypt_result = decrypt_single_file_with_params(&encrypted_path, &decrypted_path, password, &params);
        assert!(decrypt_result.is_ok(), "Decryption of special chars file failed: {:?}", decrypt_result.err());
        
        // Verify content matches exactly
        let original_content = fs::read(&original_path).expect("Failed to read original special chars file");
        let decrypted_content = fs::read(&decrypted_path).expect("Failed to read decrypted special chars file");
        assert_eq!(original_content, decrypted_content, "Decrypted special chars content does not match original");
        
        println!("✅ Special characters decryption test passed!");
    }

    #[test]
    fn test_filename_restoration_basic() {
        use shadow_crypt::decryption::restore_original_filename;
        use shadow_crypt::shared::header::Header;
        use shadow_crypt::shared::crypto::{derive_master_key, Argon2Params};
        use std::fs::File;
        use std::io::Read;

        // Create a temporary directory for test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let original_path = temp_dir.path().join("my_document.txt");
        let encrypted_path = temp_dir.path().join("encrypted.shadow");
        
        // Create a test file
        let test_content = "Test content for filename restoration";
        fs::write(&original_path, test_content).expect("Failed to write test file");
        
        let password = "restoration_test_password";
        
        // Encrypt the file (without obfuscation)
        let encrypt_result = encrypt_single_file_with_params(&original_path, &encrypted_path, password, false, &Argon2Params::test_params());
        assert!(encrypt_result.is_ok(), "Encryption failed: {:?}", encrypt_result.err());
        
        // Read the encrypted file and parse header
        let mut encrypted_data = Vec::new();
        let mut file = File::open(&encrypted_path).expect("Failed to open encrypted file");
        file.read_to_end(&mut encrypted_data).expect("Failed to read encrypted file");
        
        let (header, _) = Header::deserialize(&encrypted_data).expect("Failed to parse header");
        
        // Derive key material (use test params for fast integration testing)
        let params = Argon2Params::test_params();
        let key_material = derive_master_key(password, &header.salt, &params)
            .expect("Failed to derive key material");
        
        // Test filename restoration
        let restored_name = restore_original_filename(&header, &key_material)
            .expect("Failed to restore filename");
        
        assert_eq!(restored_name, "my_document.txt", "Restored filename doesn't match original");
        
        println!("✅ Basic filename restoration test passed!");
        println!("   Original: my_document.txt");
        println!("   Restored: {}", restored_name);
    }

    #[test]
    fn test_filename_restoration_with_obfuscation() {
        use shadow_crypt::decryption::restore_original_filename;
        use shadow_crypt::shared::header::Header;
        use shadow_crypt::shared::crypto::{derive_master_key, Argon2Params};
        use std::fs::{File, read_dir};
        use std::io::Read;

        // Create a temporary directory for test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let original_path = temp_dir.path().join("secret_file.txt");
        let output_base_path = temp_dir.path().join("obfuscated.shadow");
        
        // Create a test file
        let test_content = "Secret content that needs obfuscated filename";
        fs::write(&original_path, test_content).expect("Failed to write test file");
        
        let password = "obfuscation_test_password";
        
        // Encrypt the file WITH obfuscation
        let encrypt_result = encrypt_single_file_with_params(&original_path, &output_base_path, password, true, &Argon2Params::test_params());
        assert!(encrypt_result.is_ok(), "Obfuscated encryption failed: {:?}", encrypt_result.err());
        
        // Find the actual obfuscated file that was created
        // (since obfuscation changes the filename, we need to find the .shadow file in the directory)
        let encrypted_file_path = {
            let dir_entries = read_dir(temp_dir.path()).expect("Failed to read temp directory");
            let mut enc_files: Vec<_> = dir_entries
                .filter_map(|entry| entry.ok())
                .filter(|entry| {
                    entry.path().extension()
                        .and_then(|ext| ext.to_str())
                        .map(|ext| ext == "shadow")
                        .unwrap_or(false)
                })
                .collect();
            
            assert_eq!(enc_files.len(), 1, "Expected exactly one .shadow file, found {}", enc_files.len());
            enc_files.pop().unwrap().path()
        };
        
        // Read the encrypted file and parse header
        let mut encrypted_data = Vec::new();
        let mut file = File::open(&encrypted_file_path).expect("Failed to open obfuscated encrypted file");
        file.read_to_end(&mut encrypted_data).expect("Failed to read obfuscated encrypted file");
        
        let (header, _) = Header::deserialize(&encrypted_data).expect("Failed to parse obfuscated header");
        
        // Derive key material (use test params for fast integration testing)
        let params = Argon2Params::test_params();
        let key_material = derive_master_key(password, &header.salt, &params)
            .expect("Failed to derive key material for obfuscated file");
        
        // Test filename restoration
        let restored_name = restore_original_filename(&header, &key_material)
            .expect("Failed to restore obfuscated filename");
        
        assert_eq!(restored_name, "secret_file.txt", "Restored obfuscated filename doesn't match original");
        
        println!("✅ Obfuscated filename restoration test passed!");
        println!("   Original: secret_file.txt");
        println!("   Restored: {}", restored_name);
        println!("   Obfuscated file: {}", encrypted_file_path.display());
    }

    #[test]
    fn test_filename_restoration_unicode() {
        use shadow_crypt::decryption::restore_original_filename;
        use shadow_crypt::shared::header::Header;
        use shadow_crypt::shared::crypto::{derive_master_key, Argon2Params};
        use std::fs::File;
        use std::io::Read;

        // Create a temporary directory for test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let unicode_filename = "測試文件_тест_файл_🔒.txt";
        let original_path = temp_dir.path().join(unicode_filename);
        let encrypted_path = temp_dir.path().join("unicode_encrypted.shadow");
        
        // Create a test file with Unicode filename
        let test_content = "Unicode filename test content";
        fs::write(&original_path, test_content).expect("Failed to write Unicode test file");
        
        let password = "unicode_test_password";
        
        // Encrypt the file
        let encrypt_result = encrypt_single_file_with_params(&original_path, &encrypted_path, password, false, &Argon2Params::test_params());
        assert!(encrypt_result.is_ok(), "Unicode encryption failed: {:?}", encrypt_result.err());
        
        // Read the encrypted file and parse header
        let mut encrypted_data = Vec::new();
        let mut file = File::open(&encrypted_path).expect("Failed to open Unicode encrypted file");
        file.read_to_end(&mut encrypted_data).expect("Failed to read Unicode encrypted file");
        
        let (header, _) = Header::deserialize(&encrypted_data).expect("Failed to parse Unicode header");
        
        // Derive key material (use test params for fast integration testing)
        let params = Argon2Params::test_params();
        let key_material = derive_master_key(password, &header.salt, &params)
            .expect("Failed to derive key material for Unicode file");
        
        // Test filename restoration
        let restored_name = restore_original_filename(&header, &key_material)
            .expect("Failed to restore Unicode filename");
        
        assert_eq!(restored_name, unicode_filename, "Restored Unicode filename doesn't match original");
        
        println!("✅ Unicode filename restoration test passed!");
        println!("   Original: {}", unicode_filename);
        println!("   Restored: {}", restored_name);
    }

    #[test]
    fn test_filename_restoration_wrong_password() {
        use shadow_crypt::decryption::restore_original_filename;
        use shadow_crypt::shared::header::Header;
        use shadow_crypt::shared::crypto::{derive_master_key, Argon2Params};
        use std::fs::File;
        use std::io::Read;

        // Create a temporary directory for test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let original_path = temp_dir.path().join("password_test.txt");
        let encrypted_path = temp_dir.path().join("password_encrypted.shadow");
        
        // Create a test file
        let test_content = "Content for password test";
        fs::write(&original_path, test_content).expect("Failed to write password test file");
        
        let correct_password = "correct_password_123";
        let wrong_password = "wrong_password_456";
        
        // Encrypt the file
        let encrypt_result = encrypt_single_file_with_params(&original_path, &encrypted_path, correct_password, false, &Argon2Params::test_params());
        assert!(encrypt_result.is_ok(), "Password test encryption failed: {:?}", encrypt_result.err());
        
        // Read the encrypted file and parse header
        let mut encrypted_data = Vec::new();
        let mut file = File::open(&encrypted_path).expect("Failed to open password test encrypted file");
        file.read_to_end(&mut encrypted_data).expect("Failed to read password test encrypted file");
        
        let (header, _) = Header::deserialize(&encrypted_data).expect("Failed to parse password test header");
        
        // Derive key material with WRONG password (use test params for fast integration testing)
        let params = Argon2Params::test_params();
        let wrong_key_material = derive_master_key(wrong_password, &header.salt, &params)
            .expect("Failed to derive wrong key material");
        
        // Test filename restoration with wrong password - should fail
        let restoration_result = restore_original_filename(&header, &wrong_key_material);
        assert!(restoration_result.is_err(), "Filename restoration should fail with wrong password");
        
        // Verify correct password works
        let correct_key_material = derive_master_key(correct_password, &header.salt, &params)
            .expect("Failed to derive correct key material");
        
        let restored_name = restore_original_filename(&header, &correct_key_material)
            .expect("Failed to restore filename with correct password");
        
        assert_eq!(restored_name, "password_test.txt", "Filename restoration with correct password failed");
        
        println!("✅ Filename restoration wrong password test passed!");
        println!("   Wrong password correctly rejected");
        println!("   Correct password restored: {}", restored_name);
    }

    #[test]
    fn test_filename_restoration_empty_header() {
        use shadow_crypt::decryption::restore_original_filename;
        use shadow_crypt::shared::header::{Header, AlgorithmId};
        use shadow_crypt::shared::crypto::{derive_master_key, Argon2Params};

        // Create a header with empty encrypted filename
        let header = Header {
            magic: *b"SHADOW",
            version: 3,
            algorithm_id: AlgorithmId::AesGcm256,
            salt: [1u8; 16],
            nonce: [2u8; 12],
            directory_path_length: 0,
            encrypted_directory_path: Vec::new(),
            directory_path_auth_tag: [0u8; 16],
            filename_length: 0,
            encrypted_filename: Vec::new(), // Empty filename
            filename_auth_tag: [0u8; 16],
            metadata_length: 0,
            encrypted_metadata: Vec::new(),
            metadata_auth_tag: [0u8; 16],
            obfuscated_filename_auth_tag: [0u8; 16],
        };
        
        // Create dummy key material (use test params for fast integration testing)
        let password = "dummy_password";
        let params = Argon2Params::test_params();
        let key_material = derive_master_key(password, &header.salt, &params)
            .expect("Failed to derive dummy key material");
        
        // Test filename restoration with empty header - should fail
        let restoration_result = restore_original_filename(&header, &key_material);
        assert!(restoration_result.is_err(), "Filename restoration should fail with empty encrypted filename");
        
        println!("✅ Empty header filename restoration test passed!");
        println!("   Empty encrypted filename correctly rejected");
    }
}