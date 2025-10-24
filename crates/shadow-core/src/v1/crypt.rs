use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::Aead};

use crate::{algorithm::Algorithm, errors::CryptError};

pub fn encrypt_bytes(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<(Vec<u8>, Algorithm), CryptError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(nonce.into(), plaintext)
        .map_err(|e| CryptError::EncryptionError(format!("Encryption failed: {}", e)))?;

    Ok((ciphertext, Algorithm::XChaCha20Poly1305))
}

/// Decrypts the given ciphertext into an insecure byte vector.
pub fn decrypt_bytes_exposed(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<(Vec<u8>, Algorithm), CryptError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|e| CryptError::DecryptionError(format!("Decryption failed: {}", e)))?;

    Ok((plaintext, Algorithm::XChaCha20Poly1305))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let plaintext = b"Hello, world!";
        let key = [0u8; 32];
        let nonce = [0u8; 24];

        let (ciphertext, algorithm) = encrypt_bytes(plaintext, &key, &nonce).unwrap();
        assert_eq!(algorithm, Algorithm::XChaCha20Poly1305);
        assert_ne!(ciphertext, plaintext);

        let (decrypted, algorithm) = decrypt_bytes_exposed(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(algorithm, Algorithm::XChaCha20Poly1305);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_different_nonce_produces_different_ciphertext() {
        let plaintext = b"Test message";
        let key = [1u8; 32];
        let nonce1 = [0u8; 24];
        let nonce2 = [1u8; 24];

        let (ciphertext1, _) = encrypt_bytes(plaintext, &key, &nonce1).unwrap();
        let (ciphertext2, _) = encrypt_bytes(plaintext, &key, &nonce2).unwrap();

        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_encrypt_same_inputs_produce_same_output() {
        let plaintext = b"Deterministic test";
        let key = [2u8; 32];
        let nonce = [2u8; 24];

        let (ciphertext1, _) = encrypt_bytes(plaintext, &key, &nonce).unwrap();
        let (ciphertext2, _) = encrypt_bytes(plaintext, &key, &nonce).unwrap();

        assert_eq!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let plaintext = b"Secret message";
        let key = [3u8; 32];
        let wrong_key = [4u8; 32];
        let nonce = [3u8; 24];

        let (ciphertext, _) = encrypt_bytes(plaintext, &key, &nonce).unwrap();
        let result = decrypt_bytes_exposed(&ciphertext, &wrong_key, &nonce);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_nonce_fails() {
        let plaintext = b"Secret message";
        let key = [5u8; 32];
        let nonce = [5u8; 24];
        let wrong_nonce = [6u8; 24];

        let (ciphertext, _) = encrypt_bytes(plaintext, &key, &nonce).unwrap();
        let result = decrypt_bytes_exposed(&ciphertext, &key, &wrong_nonce);

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let plaintext = b"";
        let key = [7u8; 32];
        let nonce = [7u8; 24];

        let (ciphertext, algorithm) = encrypt_bytes(plaintext, &key, &nonce).unwrap();
        assert_eq!(algorithm, Algorithm::XChaCha20Poly1305);

        let (decrypted, algorithm) = decrypt_bytes_exposed(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(algorithm, Algorithm::XChaCha20Poly1305);
        assert_eq!(decrypted, plaintext);
    }
}
