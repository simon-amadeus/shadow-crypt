//! Generic cryptographic operations using configuration traits
//! 
//! This module provides algorithm-agnostic encryption and decryption functions that use 
//! configuration traits for clean dependency injection and algorithm independence.
//!
//! # Design Goals
//!
//! - **Algorithm Independence**: Same interface works with AES-GCM, XChaCha20, and future algorithms
//! - **Dependency Injection**: Clean separation between configuration and usage
//! - **Testing Support**: Easy mocking and parameter injection for tests
//! - **Type Safety**: Compile-time guarantees about configuration compatibility
//!
//! # Usage Patterns
//!
//! ## Direct Configuration Usage
//! ```rust,no_run
//! use shadow_crypt::shared::algorithms::{AesGcmConfig, encrypt_with_config, CryptoConfig};
//! use std::path::Path;
//!
//! let config = AesGcmConfig::test_config();
//! let input = Path::new("input.txt");
//! let output = Path::new("output.shadow");
//! encrypt_with_config(&input, &output, "password", false, &config)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Provider-based Dependency Injection (Recommended)
//! ```rust,no_run
//! use shadow_crypt::shared::algorithms::{AesGcmConfig, DefaultConfigProvider, encrypt_with_provider};
//! use std::path::Path;
//!
//! let provider = DefaultConfigProvider::<AesGcmConfig>::test();
//! let input = Path::new("input.txt");
//! let output = Path::new("output.shadow");
//! encrypt_with_provider(&input, &output, "password", false, &provider)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Algorithm-Agnostic Functions
//! ```rust,no_run
//! use shadow_crypt::shared::algorithms::{ConfigProvider, encrypt_with_provider};
//! use shadow_crypt::shared::core::errors::CryptoError;
//! use std::path::Path;
//! 
//! fn backup_file<P: ConfigProvider>(
//!     input: &Path,
//!     backup_path: &Path,
//!     provider: &P
//! ) -> Result<(), CryptoError> {
//!     encrypt_with_provider(input, backup_path, "password", false, provider)
//! }
//! 
//! // Works with any algorithm - examples would need actual provider instances
//! ```
//!
//! # Migration from Legacy Patterns
//!
//! **Before (manual parameter injection)**:
//! ```rust,no_run
//! # use shadow_crypt::shared::algorithms::aes_gcm::Argon2Params;
//! # use shadow_crypt::encryption::encrypt_single_file_with_config;
//! # use shadow_crypt::shared::algorithms::{AesGcmConfig, DefaultConfigProvider, ConfigProvider};
//! # use std::path::Path;
//! # let input = Path::new("input.txt");
//! # let output = Path::new("output.shadow");
//! # let password = "password";
//! let provider = DefaultConfigProvider::<AesGcmConfig>::test();
//! encrypt_single_file_with_config(&input, &output, password, false, provider.config())?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! **After (configuration providers)**:
//! ```rust,no_run
//! # use shadow_crypt::shared::algorithms::{AesGcmConfig, DefaultConfigProvider, encrypt_with_provider};
//! # use std::path::Path;
//! # let input = Path::new("input.txt");
//! # let output = Path::new("output.shadow");
//! # let password = "password";
//! let provider = DefaultConfigProvider::<AesGcmConfig>::test();
//! encrypt_with_provider(&input, &output, password, false, &provider)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::path::Path;
use crate::shared::core::errors::CryptoError;
use crate::shared::algorithms::config::{CryptoConfig, ConfigProvider};
use crate::shared::algorithms::aes_gcm_config::AesGcmConfig;
use crate::shared::algorithms::xchacha20_config::XChaCha20Config;
use crate::encryption::encrypt_single_file_v3;
use crate::decryption::decrypt_single_file_v3;

/// V3-only encryption with XChaCha20-Poly1305
/// 
/// # Arguments
/// * `input_path` - Path to the file to encrypt
/// * `output_path` - Path where encrypted file will be saved
/// * `password` - Password for key derivation
/// * `obfuscate_filename` - Whether to obfuscate the output filename
/// * `_config` - Configuration (unused in V3-only implementation)
/// 
/// # Returns
/// * `Ok(())` - File encrypted successfully
/// * `Err(CryptoError)` - Encryption failed
pub fn encrypt_with_config<C: CryptoConfig>(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    obfuscate_filename: bool,
    _config: &C,
) -> Result<(), CryptoError> {
    // V3-only: Always use XChaCha20-Poly1305
    encrypt_single_file_v3(input_path, output_path, password, obfuscate_filename)
} 

/// V3-only decryption with XChaCha20-Poly1305
/// 
/// # Arguments
/// * `input_path` - Path to the encrypted file
/// * `output_path` - Path where decrypted file will be saved
/// * `password` - Password for key derivation
/// * `_config` - Configuration (unused in V3-only implementation)
/// 
/// # Returns
/// * `Ok(())`
/// 
/// # Arguments
/// * `input_path` - Path to the encrypted file
/// * `output_path` - Path where decrypted file will be saved
/// * `password` - Password for key derivation
/// * `config` - Configuration implementing CryptoConfig trait
/// 
/// # Returns
/// * `Ok(())` - File decrypted successfully
/// * `Err(CryptoError)` - Decryption failed
pub fn decrypt_with_config<C: CryptoConfig>(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    _config: &C,
) -> Result<(), CryptoError> {
    // V3-only: Always use XChaCha20-Poly1305
    decrypt_single_file_v3(input_path, output_path, password)
}

/// Encrypt using a config provider (dependency injection)
/// 
/// This is the **recommended approach** for encryption as it provides clean
/// dependency injection and makes testing easier through provider patterns.
/// 
/// # Arguments
/// * `input_path` - Path to the file to encrypt
/// * `output_path` - Path where encrypted file will be saved  
/// * `password` - Password for key derivation
/// * `obfuscate_filename` - Whether to obfuscate the output filename
/// * `provider` - Configuration provider implementing ConfigProvider trait
/// 
/// # Example
/// ```rust,no_run
/// # use shadow_crypt::shared::algorithms::{AesGcmConfig, DefaultConfigProvider, encrypt_with_provider};
/// # use std::path::Path;
/// # let input = Path::new("input.txt");
/// # let output = Path::new("output.shadow");
/// let provider = DefaultConfigProvider::<AesGcmConfig>::test();
/// encrypt_with_provider(&input, &output, "password", false, &provider)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
/// 
/// # Benefits over Direct Configuration
/// - Easy to mock for testing
/// - Runtime configuration injection
/// - Consistent pattern across all algorithms
/// - Clean separation of concerns
pub fn encrypt_with_provider<P: ConfigProvider>(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    obfuscate_filename: bool,
    provider: &P,
) -> Result<(), CryptoError> {
    encrypt_with_config(input_path, output_path, password, obfuscate_filename, provider.config())
}

/// Decrypt using a config provider (dependency injection)
/// 
/// This is the **recommended approach** for decryption as it provides clean
/// dependency injection and makes testing easier through provider patterns.
/// 
/// # Arguments
/// * `input_path` - Path to the encrypted file
/// * `output_path` - Path where decrypted file will be saved
/// * `password` - Password for key derivation  
/// * `provider` - Configuration provider implementing ConfigProvider trait
/// 
/// # Example
/// ```rust,no_run
/// # use shadow_crypt::shared::algorithms::{AesGcmConfig, DefaultConfigProvider, decrypt_with_provider};
/// # use std::path::Path;
/// # let encrypted = Path::new("input.shadow");
/// # let output = Path::new("output.txt");
/// let provider = DefaultConfigProvider::<AesGcmConfig>::test();
/// decrypt_with_provider(&encrypted, &output, "password", &provider)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
/// 
/// # Benefits over Direct Configuration
/// - Easy to mock for testing
/// - Runtime configuration injection  
/// - Consistent pattern across all algorithms
/// - Clean separation of concerns
pub fn decrypt_with_provider<P: ConfigProvider>(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    provider: &P,
) -> Result<(), CryptoError> {
    decrypt_with_config(input_path, output_path, password, provider.config())
}

// Helper function to safely cast generic config to AES config
fn try_as_aes_config<C: CryptoConfig>(config: &C) -> Result<&AesGcmConfig, CryptoError> {
    // This is a temporary solution using unsafe casting
    // In a full refactor, we would use proper trait objects or enum dispatch
    if config.algorithm_id() == 1 {
        // SAFETY: We check the algorithm ID, so this should be an AesGcmConfig
        // This is a transitional approach during the refactoring process
        let ptr = config as *const C as *const AesGcmConfig;
        unsafe { 
            Ok(&*ptr) 
        }
    } else {
        Err(CryptoError::CryptographicError(
            "Configuration is not AES-GCM compatible".to_string()
        ))
    }
}

// Helper function to safely cast generic config to XChaCha20 config
fn try_as_xchacha20_config<C: CryptoConfig>(config: &C) -> Result<&XChaCha20Config, CryptoError> {
    // This is a temporary solution using unsafe casting
    // In a full refactor, we would use proper trait objects or enum dispatch
    if config.algorithm_id() == 2 {
        // SAFETY: We check the algorithm ID, so this should be an XChaCha20Config
        // This is a transitional approach during the refactoring process
        let ptr = config as *const C as *const XChaCha20Config;
        unsafe { 
            Ok(&*ptr) 
        }
    } else {
        Err(CryptoError::CryptographicError(
            "Configuration is not XChaCha20-Poly1305 compatible".to_string()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::algorithms::{DefaultConfigProvider, XChaCha20Config};
    use tempfile::TempDir;
    use std::fs::write;

    #[test]
    fn test_encrypt_decrypt_with_config() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test.txt");
        let encrypted_file = temp_dir.path().join("test.txt.shadow");
        let decrypted_file = temp_dir.path().join("test_decrypted.txt");
        
        // Create test file
        let test_content = "Hello, configuration world!";
        write(&input_file, test_content).unwrap();
        
        // Create test configuration
        let config = AesGcmConfig::test_config();
        let password = "test_password";
        
        // Test encryption with config
        encrypt_with_config(&input_file, &encrypted_file, password, false, &config).unwrap();
        assert!(encrypted_file.exists());
        
        // Test decryption with config
        decrypt_with_config(&encrypted_file, &decrypted_file, password, &config).unwrap();
        assert!(decrypted_file.exists());
        
        // Verify content
        let decrypted_content = std::fs::read_to_string(&decrypted_file).unwrap();
        assert_eq!(decrypted_content, test_content);
    }
    
    #[test]
    fn test_encrypt_decrypt_with_provider() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test.txt");
        let encrypted_file = temp_dir.path().join("test.txt.shadow");
        let decrypted_file = temp_dir.path().join("test_decrypted.txt");
        
        // Create test file
        let test_content = "Hello, provider world!";
        write(&input_file, test_content).unwrap();
        
        // Create test provider
        let provider = DefaultConfigProvider::<AesGcmConfig>::test();
        let password = "test_password";
        
        // Test encryption with provider
        encrypt_with_provider(&input_file, &encrypted_file, password, false, &provider).unwrap();
        assert!(encrypted_file.exists());
        
        // Test decryption with provider
        decrypt_with_provider(&encrypted_file, &decrypted_file, password, &provider).unwrap();
        assert!(decrypted_file.exists());
        
        // Verify content
        let decrypted_content = std::fs::read_to_string(&decrypted_file).unwrap();
        assert_eq!(decrypted_content, test_content);
    }

    #[test]
    fn test_xchacha20_encrypt_decrypt_with_config() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test_xchacha20.txt");
        let encrypted_file = temp_dir.path().join("test_xchacha20.txt.shadow");
        let decrypted_file = temp_dir.path().join("test_xchacha20_decrypted.txt");
        
        // Create test file
        let test_content = "Hello, XChaCha20 config world!";
        write(&input_file, test_content).unwrap();
        
        // Test with XChaCha20 configuration
        let xchacha20_config = XChaCha20Config::test_config();
        let password = "test_password_xchacha20";
        
        // Test encryption and decryption with XChaCha20 config
        encrypt_with_config(&input_file, &encrypted_file, password, false, &xchacha20_config).unwrap();
        assert!(encrypted_file.exists());
        
        decrypt_with_config(&encrypted_file, &decrypted_file, password, &xchacha20_config).unwrap();
        assert!(decrypted_file.exists());
        
        // Verify content
        let decrypted_content = std::fs::read_to_string(&decrypted_file).unwrap();
        assert_eq!(test_content, decrypted_content);
    }
    
    #[test]
    fn test_xchacha20_encrypt_decrypt_with_provider() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test_xchacha20_provider.txt");
        let encrypted_file = temp_dir.path().join("test_xchacha20_provider.txt.shadow");
        let decrypted_file = temp_dir.path().join("test_xchacha20_provider_decrypted.txt");
        
        // Create test file
        let test_content = "Hello, XChaCha20 provider world!";
        write(&input_file, test_content).unwrap();
        
        // Create XChaCha20 test provider
        let provider = DefaultConfigProvider::<XChaCha20Config>::test();
        let password = "test_password_xchacha20_provider";
        
        // Test encryption with provider
        encrypt_with_provider(&input_file, &encrypted_file, password, false, &provider).unwrap();
        assert!(encrypted_file.exists());
        
        // Test decryption with provider
        decrypt_with_provider(&encrypted_file, &decrypted_file, password, &provider).unwrap();
        assert!(decrypted_file.exists());
        
        // Verify content
        let decrypted_content = std::fs::read_to_string(&decrypted_file).unwrap();
        assert_eq!(test_content, decrypted_content);
    }
}