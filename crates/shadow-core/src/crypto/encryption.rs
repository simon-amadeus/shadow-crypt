// shadow-core/src/crypto/encryption.rs
// Encryption and decryption operations
// All code related to encrypting and decrypting data lives here

use super::keys::derive_filename_key;
use crate::errors::CryptoError;
use crate::memory::SecureKey;

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};

/// Encrypt content using XChaCha20-Poly1305 with associated data
/// Pure function - deterministic with same inputs
pub fn encrypt_content(
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
pub fn decrypt_content(
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
    master_key: &SecureKey,
    nonce: &[u8; 24],
) -> Result<Vec<u8>, CryptoError> {
    // Derive filename-specific key
    let filename_key = derive_filename_key(master_key)?;

    // Encrypt filename using main function with empty AAD
    encrypt_content(filename.as_bytes(), &filename_key, nonce, &[])
}

/// Decrypt filename using derived filename key
/// Pure function - deterministic with same inputs
pub fn decrypt_filename(
    ciphertext: &[u8],
    master_key: &SecureKey,
    nonce: &[u8; 24],
) -> Result<String, CryptoError> {
    // Derive filename-specific key
    let filename_key = derive_filename_key(master_key)?;

    // Decrypt filename using main function with empty AAD
    let plaintext = decrypt_content(ciphertext, &filename_key, nonce, &[])?;

    // Convert to string
    String::from_utf8(plaintext).map_err(|_| CryptoError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_content_roundtrip() {
        let plaintext = b"Hello, World!";
        let key = SecureKey::new([42u8; 32]);
        let nonce = [1u8; 24];
        let aad = b"header_data";

        let ciphertext = encrypt_content(plaintext, &key, &nonce, aad).unwrap();
        let decrypted = decrypt_content(&ciphertext, &key, &nonce, aad).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_content_different_aad_fails() {
        let plaintext = b"Hello, World!";
        let key = SecureKey::new([42u8; 32]);
        let nonce = [1u8; 24];
        let aad1 = b"header_data1";
        let aad2 = b"header_data2";

        let ciphertext = encrypt_content(plaintext, &key, &nonce, aad1).unwrap();
        let result = decrypt_content(&ciphertext, &key, &nonce, aad2);

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_filename_roundtrip() {
        let filename = "test_file.txt";
        let master_key = SecureKey::new([42u8; 32]);
        let nonce = [1u8; 24];

        let ciphertext = encrypt_filename(filename, &master_key, &nonce).unwrap();
        let decrypted = decrypt_filename(&ciphertext, &master_key, &nonce).unwrap();

        assert_eq!(filename, decrypted);
    }

    #[test]
    fn test_encrypt_filename_deterministic() {
        let filename = "test_file.txt";
        let master_key = SecureKey::new([42u8; 32]);
        let nonce = [1u8; 24];

        let ciphertext1 = encrypt_filename(filename, &master_key, &nonce).unwrap();
        let ciphertext2 = encrypt_filename(filename, &master_key, &nonce).unwrap();

        assert_eq!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_encrypt_filename_different_nonces() {
        let filename = "test_file.txt";
        let master_key = SecureKey::new([42u8; 32]);
        let nonce1 = [1u8; 24];
        let nonce2 = [2u8; 24];

        let ciphertext1 = encrypt_filename(filename, &master_key, &nonce1).unwrap();
        let ciphertext2 = encrypt_filename(filename, &master_key, &nonce2).unwrap();

        assert_ne!(ciphertext1, ciphertext2);
    }
}
