//! Filename restoration implementation
//! 
//! This module provides functionality to restore original filenames from encrypted
//! file headers, supporting both obfuscated and non-obfuscated files.

use crate::shared::errors::CryptoError;
use crate::shared::header::Header;
use crate::shared::core::crypto::KeyMaterial;
use crate::shared::algorithms::aes_gcm::decrypt_aes_gcm;

/// Restore original filename from encrypted header
/// 
/// Decrypts the original filename stored in the file header during encryption.
/// This works for both obfuscated and non-obfuscated files, as the original
/// filename is always encrypted and stored in the header.
/// 
/// # Arguments
/// * `header` - Parsed file header containing encrypted filename
/// * `keys` - Key material derived from password for decryption
/// 
/// # Returns
/// * `Ok(String)` - Original filename as UTF-8 string
/// * `Err(CryptoError)` - Restoration failed (wrong password, corruption, etc.)
/// 
/// # Security
/// * Uses AES-256-GCM for authenticated decryption
/// * Validates UTF-8 encoding of restored filename
/// * Fails securely on authentication or decryption errors
/// 
/// # Usage
/// ```rust,no_run
/// use shadow_crypt::decryption::restore_original_filename;
/// use shadow_crypt::shared::header::Header;
/// use shadow_crypt::shared::algorithms::aes_gcm::{derive_master_key, Argon2Params};
/// 
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let encrypted_data = vec![]; // dummy data
/// # let password = "example_password";
/// # let params = Argon2Params::default();
/// let (header, _) = Header::deserialize(&encrypted_data)?;
/// let keys = derive_master_key(password, &header.salt, &params)?;
/// let original_name = restore_original_filename(&header, &keys)?;
/// # Ok(())
/// # }
/// ```
pub fn restore_original_filename(
    header: &Header,
    keys: &KeyMaterial
) -> Result<String, CryptoError> {
    // Check if header contains an encrypted filename
    if header.encrypted_filename.is_empty() {
        return Err(CryptoError::CryptographicError(
            "No encrypted filename found in header".to_string()
        ));
    }
    
    // Decrypt the filename using AES-256-GCM
    let filename_bytes = decrypt_aes_gcm(
        keys.encryption_key.expose_secret(),
        &header.nonce,
        &header.encrypted_filename,
        &[] // No additional authenticated data for filename
    ).map_err(|e| CryptoError::CryptographicError(
        format!("Failed to decrypt filename: {}", e)
    ))?;
    
    // Convert decrypted bytes to UTF-8 string
    let original_filename = String::from_utf8(filename_bytes)
        .map_err(|e| CryptoError::CryptographicError(
            format!("Invalid UTF-8 in decrypted filename: {}", e)
        ))?;
    
    // Validate that the filename is not empty
    if original_filename.is_empty() {
        return Err(CryptoError::CryptographicError(
            "Decrypted filename is empty".to_string()
        ));
    }
    
    Ok(original_filename)
}