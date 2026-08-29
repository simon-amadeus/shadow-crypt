use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};

use crate::{algorithm::Algorithm, errors::CryptError, memory::SecureBytes};

/// Encrypts the given plaintext, authenticating `aad` alongside it.
///
/// In v3 the associated data is always a serialized
/// [`HeaderBinding`](crate::v3::header::HeaderBinding), which ties the
/// ciphertext to its header and its purpose (metadata vs content).
pub fn encrypt_bytes(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
) -> Result<(Vec<u8>, Algorithm), CryptError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| CryptError::EncryptionError(format!("Encryption failed: {}", e)))?;

    Ok((ciphertext, Algorithm::XChaCha20Poly1305))
}

/// Decrypts the given ciphertext, returning the plaintext as zeroizing [`SecureBytes`].
///
/// Fails if the ciphertext or the associated data does not authenticate.
pub fn decrypt_bytes(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
) -> Result<(SecureBytes, Algorithm), CryptError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        // The AEAD reports authentication failure without a cause; wrong
        // password and corruption are indistinguishable by design.
        .map_err(|_| {
            CryptError::DecryptionError(
                "authentication failed (wrong password, or the file is corrupted)".to_string(),
            )
        })?;

    Ok((SecureBytes::new(plaintext), Algorithm::XChaCha20Poly1305))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let plaintext = b"Hello, world!";
        let key = [0u8; 32];
        let nonce = [0u8; 24];
        let aad = b"header binding";

        let (ciphertext, algorithm) = encrypt_bytes(plaintext, &key, &nonce, aad).unwrap();
        assert_eq!(algorithm, Algorithm::XChaCha20Poly1305);
        assert_ne!(ciphertext, plaintext);

        let (decrypted, _) = decrypt_bytes(&ciphertext, &key, &nonce, aad).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_aad_fails() {
        let plaintext = b"Secret message";
        let key = [1u8; 32];
        let nonce = [1u8; 24];

        let (ciphertext, _) = encrypt_bytes(plaintext, &key, &nonce, b"aad one").unwrap();
        let result = decrypt_bytes(&ciphertext, &key, &nonce, b"aad two");

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let plaintext = b"Secret message";
        let key = [3u8; 32];
        let wrong_key = [4u8; 32];
        let nonce = [3u8; 24];
        let aad = b"aad";

        let (ciphertext, _) = encrypt_bytes(plaintext, &key, &nonce, aad).unwrap();
        assert!(decrypt_bytes(&ciphertext, &wrong_key, &nonce, aad).is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_nonce_fails() {
        let plaintext = b"Secret message";
        let key = [5u8; 32];
        let nonce = [5u8; 24];
        let wrong_nonce = [6u8; 24];
        let aad = b"aad";

        let (ciphertext, _) = encrypt_bytes(plaintext, &key, &nonce, aad).unwrap();
        assert!(decrypt_bytes(&ciphertext, &key, &wrong_nonce, aad).is_err());
    }

    #[test]
    fn test_encrypt_empty_plaintext_and_empty_aad() {
        let plaintext = b"";
        let key = [7u8; 32];
        let nonce = [7u8; 24];
        let aad = b"";

        let (ciphertext, _) = encrypt_bytes(plaintext, &key, &nonce, aad).unwrap();
        let (decrypted, _) = decrypt_bytes(&ciphertext, &key, &nonce, aad).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }
}
