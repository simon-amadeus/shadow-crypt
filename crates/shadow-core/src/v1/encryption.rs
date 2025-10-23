use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::Aead};

pub fn encrypt_bytes(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<Vec<u8>, EncryptionError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(nonce.into(), plaintext)
        .map_err(|e| EncryptionError::EncryptionError(format!("Encryption failed: {}", e)))?;

    Ok(ciphertext)
}

pub enum EncryptionError {
    EncryptionError(String),
}
