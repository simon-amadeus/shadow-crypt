// shadow-core/src/crypto.rs
// Pure cryptographic functions with no side effects
// All functions are deterministic with same inputs

use crate::types::{SecureString, SecureKey};
use crate::errors::CryptoError;

use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use subtle::ConstantTimeEq;

/// Derive a cryptographic key from password and salt using Argon2id
/// Pure function - deterministic with same inputs
pub fn derive_key(password: &SecureString, salt: &[u8; 16]) -> Result<SecureKey, CryptoError> {
    let argon2 = Argon2::default();
    
    // Convert salt to required format
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|_| CryptoError::KeyDerivation)?;
    
    // Hash the password
    let password_hash = argon2
        .hash_password(password.as_str().as_bytes(), &salt_string)
        .map_err(|_| CryptoError::KeyDerivation)?;
    
    // Extract the hash bytes
    let hash_option = password_hash.hash
        .ok_or(CryptoError::KeyDerivation)?;
    let hash_bytes = hash_option.as_bytes();
    
    if hash_bytes.len() < 32 {
        return Err(CryptoError::KeyDerivation);
    }
    
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&hash_bytes[..32]);
    
    Ok(SecureKey::new(key_bytes))
}

/// Encrypt content using XChaCha20-Poly1305 with associated data
/// Pure function - deterministic with same inputs
pub fn encrypt_content(
    plaintext: &[u8],
    key: &SecureKey,
    nonce: &[u8; 24],
    aad: &[u8], // associated data (header)
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| CryptoError::InvalidKey { expected: 32, actual: key.as_bytes().len() })?;
    
    let xnonce = XNonce::from_slice(nonce);
    
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    
    cipher
        .encrypt(xnonce, payload)
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
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| CryptoError::InvalidKey { expected: 32, actual: key.as_bytes().len() })?;
    
    let xnonce = XNonce::from_slice(nonce);
    
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    
    cipher
        .decrypt(xnonce, payload)
        .map_err(|_| CryptoError::Decryption)
}

/// Encrypt filename using derived filename key
/// Pure function - deterministic with same inputs
pub fn encrypt_filename(
    filename: &str,
    master_key: &SecureKey,
    nonce: &[u8; 24],
) -> Result<Vec<u8>, CryptoError> {
    // Derive filename-specific key using HKDF
    let filename_key = derive_filename_key(master_key)?;
    
    // Encrypt the filename
    encrypt_with_key(filename.as_bytes(), &filename_key, nonce)
}

/// Decrypt filename using derived filename key
/// Pure function - deterministic with same inputs
pub fn decrypt_filename(
    ciphertext: &[u8],
    master_key: &SecureKey,
    nonce: &[u8; 24],
) -> Result<String, CryptoError> {
    // Derive filename-specific key using HKDF
    let filename_key = derive_filename_key(master_key)?;
    
    // Decrypt the filename
    let plaintext = decrypt_with_key(ciphertext, &filename_key, nonce)?;
    
    // Convert back to string
    String::from_utf8(plaintext)
        .map_err(|_| CryptoError::Decryption)
}

/// Derive filename encryption key from master key using HKDF
/// Pure function - deterministic with same inputs
fn derive_filename_key(master_key: &SecureKey) -> Result<SecureKey, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, master_key.as_bytes());
    let mut derived_key = [0u8; 32];
    
    hk.expand(b"filename", &mut derived_key)
        .map_err(|_| CryptoError::HkdfDerivation)?;
    
    Ok(SecureKey::new(derived_key))
}

/// Encrypt data with a specific key (helper function)
/// Pure function - deterministic with same inputs
fn encrypt_with_key(
    data: &[u8],
    key: &SecureKey,
    nonce: &[u8; 24],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| CryptoError::InvalidKey { expected: 32, actual: key.as_bytes().len() })?;
    
    let xnonce = XNonce::from_slice(nonce);
    
    cipher
        .encrypt(xnonce, data)
        .map_err(|_| CryptoError::Encryption)
}

/// Decrypt data with a specific key (helper function)
/// Pure function - deterministic with same inputs
fn decrypt_with_key(
    ciphertext: &[u8],
    key: &SecureKey,
    nonce: &[u8; 24],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| CryptoError::InvalidKey { expected: 32, actual: key.as_bytes().len() })?;
    
    let xnonce = XNonce::from_slice(nonce);
    
    cipher
        .decrypt(xnonce, ciphertext)
        .map_err(|_| CryptoError::Decryption)
}

/// Hash content using SHA-256
/// Pure function - deterministic with same inputs
pub fn hash_content(content: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(content);
    hasher.finalize().into()
}

/// Generate cryptographically secure random nonce
/// Pure with external entropy source
pub fn generate_nonce() -> Result<[u8; 24], CryptoError> {
    let mut nonce = [0u8; 24];
    // Use ChaCha20Poly1305's RNG for generating random values
    use chacha20poly1305::aead::{rand_core::RngCore, OsRng};
    OsRng.fill_bytes(&mut nonce);
    Ok(nonce)
}

/// Generate cryptographically secure random salt
/// Pure with external entropy source
pub fn generate_salt() -> Result<[u8; 16], CryptoError> {
    let mut salt = [0u8; 16];
    // Use ChaCha20Poly1305's RNG for generating random values
    use chacha20poly1305::aead::{rand_core::RngCore, OsRng};
    OsRng.fill_bytes(&mut salt);
    Ok(salt)
}

/// Constant-time comparison of byte arrays
/// Pure function - prevents timing attacks
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let password = SecureString::new("test_password".to_string());
        let salt = [1u8; 16];
        
        let key1 = derive_key(&password, &salt).unwrap();
        let key2 = derive_key(&password, &salt).unwrap();
        
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_derive_key_different_salts() {
        let password = SecureString::new("test_password".to_string());
        let salt1 = [1u8; 16];
        let salt2 = [2u8; 16];
        
        let key1 = derive_key(&password, &salt1).unwrap();
        let key2 = derive_key(&password, &salt2).unwrap();
        
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_content() {
        let plaintext = b"Hello, World!";
        let key = SecureKey::new([42u8; 32]);
        let nonce = [1u8; 24];
        let aad = b"associated_data";
        
        let ciphertext = encrypt_content(plaintext, &key, &nonce, aad).unwrap();
        let decrypted = decrypt_content(&ciphertext, &key, &nonce, aad).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_content_wrong_aad() {
        let plaintext = b"Hello, World!";
        let key = SecureKey::new([42u8; 32]);
        let nonce = [1u8; 24];
        let aad1 = b"associated_data";
        let aad2 = b"wrong_aad";
        
        let ciphertext = encrypt_content(plaintext, &key, &nonce, aad1).unwrap();
        let result = decrypt_content(&ciphertext, &key, &nonce, aad2);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_filename() {
        let filename = "test_file.txt";
        let master_key = SecureKey::new([42u8; 32]);
        let nonce = [1u8; 24];
        
        let ciphertext = encrypt_filename(filename, &master_key, &nonce).unwrap();
        let decrypted = decrypt_filename(&ciphertext, &master_key, &nonce).unwrap();
        
        assert_eq!(filename, decrypted);
    }

    #[test]
    fn test_hash_content_deterministic() {
        let content = b"test content";
        let hash1 = hash_content(content);
        let hash2 = hash_content(content);
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_content_different_inputs() {
        let content1 = b"test content 1";
        let content2 = b"test content 2";
        
        let hash1 = hash_content(content1);
        let hash2 = hash_content(content2);
        
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce().unwrap();
        let nonce2 = generate_nonce().unwrap();
        
        // Very unlikely to be the same
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt().unwrap();
        let salt2 = generate_salt().unwrap();
        
        // Very unlikely to be the same
        assert_ne!(salt1, salt2);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";
        let d = b"hi"; // different length
        
        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, d));
    }

    #[test]
    fn test_derive_filename_key_deterministic() {
        let master_key = SecureKey::new([42u8; 32]);
        
        let filename_key1 = derive_filename_key(&master_key).unwrap();
        let filename_key2 = derive_filename_key(&master_key).unwrap();
        
        assert_eq!(filename_key1.as_bytes(), filename_key2.as_bytes());
    }

    #[test]
    fn test_derive_filename_key_different_master() {
        let master_key1 = SecureKey::new([42u8; 32]);
        let master_key2 = SecureKey::new([43u8; 32]);
        
        let filename_key1 = derive_filename_key(&master_key1).unwrap();
        let filename_key2 = derive_filename_key(&master_key2).unwrap();
        
        assert_ne!(filename_key1.as_bytes(), filename_key2.as_bytes());
    }
}