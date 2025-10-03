//! Integration tests for filename authentication security
//!
//! These tests verify that the filename authentication prevents file
//! substitution attacks in obfuscated mode.

use shadow_crypt::encryption::encrypt_single_file_with_config;
use shadow_crypt::decryption::decrypt_single_file_with_config;
use shadow_crypt::shared::algorithms::aes_gcm_config::AesGcmConfig;
use shadow_crypt::shared::algorithms::config::CryptoConfig;
use std::fs::{write, read};
use tempfile::TempDir;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filename_authentication_prevents_substitution_attack() {
        // Create temporary directory for test
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        
        // Create two different files
        let file1_path = temp_path.join("secret1.txt");
        let file2_path = temp_path.join("secret2.txt");
        let file1_content = b"This is secret file 1";
        let file2_content = b"This is secret file 2";
        
        write(&file1_path, file1_content).unwrap();
        write(&file2_path, file2_content).unwrap();
        
        // Encrypt both files with obfuscation
        let password = "test_password_123";
        let params = Argon2Params::test_params();
        
        let encrypted1_path = temp_path.join("encrypted1.shadow");
        let encrypted2_path = temp_path.join("encrypted2.shadow");
        
        encrypt_single_file_with_params(
            &file1_path,
            &encrypted1_path,
            password,
            true, // obfuscate filename
            &params
        ).unwrap();
        
        encrypt_single_file_with_params(
            &file2_path,
            &encrypted2_path,
            password,
            true, // obfuscate filename
            &params
        ).unwrap();
        
        // Get the actual obfuscated filenames and determine which is which
        let mut obfuscated_files: Vec<_> = std::fs::read_dir(temp_path).unwrap()
            .filter_map(|entry| {
                let entry = entry.unwrap();
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".shadow") && name != "encrypted1.shadow" && name != "encrypted2.shadow" {
                    Some(entry.path())
                } else {
                    None
                }
            })
            .collect();
        
        assert_eq!(obfuscated_files.len(), 2, "Should have exactly 2 obfuscated files");
        obfuscated_files.sort(); // Ensure consistent ordering
        
        // We need to determine which obfuscated file contains which content
        // Decrypt each one to see which contains file1 vs file2 content
        let mut file1_obfuscated_path = None;
        let mut file2_obfuscated_path = None;
        
        for obfuscated_path in &obfuscated_files {
            let test_decrypted_path = temp_path.join("test_decrypt.txt");
            decrypt_single_file_with_params(
                obfuscated_path,
                &test_decrypted_path,
                password,
                &params
            ).unwrap();
            
            let content = read(&test_decrypted_path).unwrap();
            if content == file1_content {
                file1_obfuscated_path = Some(obfuscated_path);
            } else if content == file2_content {
                file2_obfuscated_path = Some(obfuscated_path);
            }
            
            std::fs::remove_file(&test_decrypted_path).unwrap(); // Clean up
        }
        
        let actual_encrypted1_path = file1_obfuscated_path.unwrap();
        let actual_encrypted2_path = file2_obfuscated_path.unwrap();
        let obfuscated1_name = actual_encrypted1_path.file_name().unwrap().to_str().unwrap();
        let obfuscated2_name = actual_encrypted2_path.file_name().unwrap().to_str().unwrap();
        
        // Verify they are different
        assert_ne!(obfuscated1_name, obfuscated2_name);
        
        // Normal decryption should work
        let decrypted1_path = temp_path.join("decrypted1.txt");
        println!("Decrypting file: {}", actual_encrypted1_path.display());
        decrypt_single_file_with_params(
            actual_encrypted1_path,
            &decrypted1_path,
            password,
            &params
        ).unwrap();
        
        let decrypted1_content = read(&decrypted1_path).unwrap();
        println!("Expected: {:?}", String::from_utf8_lossy(file1_content));
        println!("Got: {:?}", String::from_utf8_lossy(&decrypted1_content));
        assert_eq!(decrypted1_content, file1_content);
        
        // Now attempt a file substitution attack:
        // Copy encrypted2's content to encrypted1's filename
        let attack_path = temp_path.join(obfuscated1_name);
        let encrypted2_content = read(actual_encrypted2_path).unwrap();
        write(&attack_path, &encrypted2_content).unwrap();
        
        println!("Attack setup:");
        println!("  obfuscated1_name: {}", obfuscated1_name);
        println!("  obfuscated2_name: {}", obfuscated2_name);
        println!("  attack_path: {}", attack_path.display());
        println!("  copied content from: {}", actual_encrypted2_path.display());
        
        // Try to decrypt the substituted file - this should fail due to filename auth
        let attacked_decrypted_path = temp_path.join("attacked_decrypted.txt");
        println!("Attempting to decrypt attack file: {}", attack_path.display());
        let result = decrypt_single_file_with_params(
            &attack_path,
            &attacked_decrypted_path,
            password,
            &params
        );
        
        // The decryption should fail with a file substitution error
        if result.is_ok() {
            // If it didn't fail, let's see what content we got
            let decrypted_attack_content = read(&attacked_decrypted_path).unwrap();
            panic!("Expected filename authentication to fail, but decryption succeeded! Got content: {:?}", 
                String::from_utf8_lossy(&decrypted_attack_content));
        }
        
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("substitution attack"));
        assert!(error_msg.contains("filename does not match"));
    }
    
    #[test]
    fn test_filename_authentication_allows_legitimate_files() {
        // Create temporary directory for test
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        
        // Create a file
        let file_path = temp_path.join("legitimate.txt");
        let file_content = b"This is a legitimate file";
        write(&file_path, file_content).unwrap();
        
        // Encrypt with obfuscation
        let password = "test_password_456";
        let params = Argon2Params::test_params();
        
        let encrypted_path = temp_path.join("encrypted.shadow");
        encrypt_single_file_with_params(
            &file_path,
            &encrypted_path,
            password,
            true, // obfuscate filename
            &params
        ).unwrap();
        
        // Find the actual obfuscated file
        let actual_encrypted_path = std::fs::read_dir(temp_path).unwrap()
            .find_map(|entry| {
                let entry = entry.unwrap();
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".shadow") && name != "encrypted.shadow" {
                    Some(entry.path())
                } else {
                    None
                }
            })
            .expect("Should find the obfuscated file");
        
        // Move the file to a different directory (simulating normal file operations)
        let new_dir = temp_path.join("moved");
        std::fs::create_dir(&new_dir).unwrap();
        let moved_path = new_dir.join(actual_encrypted_path.file_name().unwrap());
        std::fs::rename(&actual_encrypted_path, &moved_path).unwrap();
        
        // Decryption should still work (filename is still legitimate)
        let decrypted_path = temp_path.join("decrypted.txt");
        decrypt_single_file_with_params(
            &moved_path,
            &decrypted_path,
            password,
            &params
        ).unwrap();
        
        let decrypted_content = read(&decrypted_path).unwrap();
        assert_eq!(decrypted_content, file_content);
    }
    
    #[test]
    fn test_non_obfuscated_files_bypass_filename_auth() {
        // Create temporary directory for test
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        
        // Create a file
        let file_path = temp_path.join("normal.txt");
        let file_content = b"This is a normal file";
        write(&file_path, file_content).unwrap();
        
        // Encrypt WITHOUT obfuscation
        let password = "test_password_789";
        let params = Argon2Params::test_params();
        
        let encrypted_path = temp_path.join("normal.txt.shadow");
        encrypt_single_file_with_params(
            &file_path,
            &encrypted_path,
            password,
            false, // NO obfuscation
            &params
        ).unwrap();
        
        // Decryption should work (no filename auth for non-obfuscated files)
        let decrypted_path = temp_path.join("decrypted_normal.txt");
        decrypt_single_file_with_params(
            &encrypted_path,
            &decrypted_path,
            password,
            &params
        ).unwrap();
        
        let decrypted_content = read(&decrypted_path).unwrap();
        assert_eq!(decrypted_content, file_content);
    }
}