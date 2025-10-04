//! V3-only filename restoration implementation

use crate::shared::core::errors::CryptoError;
use crate::shared::header::Header;
use crate::shared::versions::v3::TlvFieldType;
use crate::shared::algorithms::xchacha20_poly1305::decrypt_xchacha20_poly1305;

/// Restore original filename from V3 TLV fields
pub fn restore_original_filename(
    header: &Header,
    master_key: &[u8]
) -> Result<String, CryptoError> {
    // Check if header contains an encrypted filename in TLV fields
    let encrypted_filename = header.tlv_fields.get_field(TlvFieldType::OriginalFilename)
        .ok_or_else(|| CryptoError::CryptographicError(
            "No encrypted filename found in TLV fields".to_string()
        ))?;
    
    // Decrypt the filename using XChaCha20-Poly1305
    let filename_bytes = decrypt_xchacha20_poly1305(
        master_key,
        &header.nonce,
        encrypted_filename,
        &[]
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