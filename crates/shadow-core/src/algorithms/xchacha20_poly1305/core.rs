// shadow-core/src/crypto/algorithms/xchacha20_poly1305/core.rs
// XChaCha20-Poly1305 encryption implementation
// Pure crypto functions with no side effects except for randomness generation

use crate::errors::CryptoError;
use crate::memory::SecureKey;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};

/// Generate cryptographically secure random nonce for XChaCha20
/// This function has side effects (uses system randomness)
pub fn generate_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    rand::fill(&mut nonce);
    nonce
}

/// Encrypt content using XChaCha20-Poly1305 with associated data
/// Pure function - deterministic with same inputs
pub fn encrypt(
    plaintext: &[u8],
    key: &SecureKey,
    nonce: &[u8; 24],
    aad: &[u8], // associated data (header)
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::InvalidKey {
            expected: 32,
            actual: key.as_bytes().len(),
        })?;

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(nonce.into(), payload)
        .map_err(|_| CryptoError::Encryption)
}

/// Decrypt content using XChaCha20-Poly1305 with associated data
/// Pure function - deterministic with same inputs
pub fn decrypt(
    ciphertext: &[u8],
    key: &SecureKey,
    nonce: &[u8; 24],
    aad: &[u8], // associated data (header)
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::InvalidKey {
            expected: 32,
            actual: key.as_bytes().len(),
        })?;

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce.into(), payload)
        .map_err(|_| CryptoError::Decryption)
}

/// Encrypt filename using derived filename key
/// Pure function - deterministic with same inputs
pub fn encrypt_filename(
    filename: &str,
    filename_key: &SecureKey,
    nonce: &[u8; 24],
) -> Result<Vec<u8>, CryptoError> {
    // Encrypt filename using main function with empty AAD
    encrypt(filename.as_bytes(), filename_key, nonce, &[])
}

/// Decrypt filename using derived filename key
/// Pure function - deterministic with same inputs
pub fn decrypt_filename(
    ciphertext: &[u8],
    filename_key: &SecureKey,
    nonce: &[u8; 24],
) -> Result<String, CryptoError> {
    // Decrypt filename using main function with empty AAD
    let plaintext = decrypt(ciphertext, filename_key, nonce, &[])?;

    // Convert to string
    String::from_utf8(plaintext).map_err(|_| CryptoError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello, World!";
        let key = SecureKey::new([42u8; 32]);
        let nonce = [1u8; 24];
        let aad = b"test_aad";

        let ciphertext = encrypt(plaintext, &key, &nonce, aad).unwrap();
        let decrypted = decrypt(&ciphertext, &key, &nonce, aad).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_filename_encrypt_decrypt_roundtrip() {
        let filename = "test_file.txt";
        let key = SecureKey::new([42u8; 32]);
        let nonce = [1u8; 24];

        let ciphertext = encrypt_filename(filename, &key, &nonce).unwrap();
        let decrypted = decrypt_filename(&ciphertext, &key, &nonce).unwrap();

        assert_eq!(filename, decrypted);
    }
}
