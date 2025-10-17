// shadow-core/src/crypto/keys.rs
// Key derivation and key management operations
// All code related to generating and deriving keys lives here

use crate::errors::CryptoError;
use crate::memory::{SecureKey, SecureString};

use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a cryptographic key from password and salt using Argon2id
/// Pure function - deterministic with same inputs
///
/// # Parameters
///
/// * `password` - The password to derive the key from
/// * `salt` - 16-byte salt for key derivation  
/// * `argon2` - Configured Argon2 instance with desired parameters
pub fn derive_key(
    password: &SecureString,
    salt: &[u8; 16],
    argon2: &Argon2,
) -> Result<SecureKey, CryptoError> {
    // Convert salt to required format
    let salt_string = SaltString::encode_b64(salt).map_err(|_| CryptoError::KeyDerivation)?;

    // Hash the password
    let password_hash = argon2
        .hash_password(password.as_str().as_bytes(), &salt_string)
        .map_err(|_| CryptoError::KeyDerivation)?;

    // Extract the hash bytes
    let hash_option = password_hash.hash.ok_or(CryptoError::KeyDerivation)?;
    let hash_bytes = hash_option.as_bytes();

    if hash_bytes.len() < 32 {
        return Err(CryptoError::KeyDerivation);
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&hash_bytes[..32]);

    Ok(SecureKey::new(key_bytes))
}

/// Derive a filename-specific key using HKDF
/// Pure function - deterministic with same inputs
pub fn derive_filename_key(master_key: &SecureKey) -> Result<SecureKey, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, master_key.as_bytes());
    let mut filename_key = [0u8; 32];

    hkdf.expand(b"filename", &mut filename_key)
        .map_err(|_| CryptoError::HkdfDerivation)?;

    Ok(SecureKey::new(filename_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{Algorithm, Argon2, Params, Version};

    fn create_test_argon2() -> Argon2<'static> {
        let params = Params::new(64, 1, 1, None).expect("Test Argon2 parameters should be valid");
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    }

    #[test]
    fn test_derive_key_basic() {
        let password = SecureString::new("test_password".to_string());
        let salt = [1u8; 16];
        let argon2 = create_test_argon2();

        let result = derive_key(&password, &salt, &argon2);
        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_key_deterministic() {
        let password = SecureString::new("test_password".to_string());
        let salt = [1u8; 16];
        let argon2 = create_test_argon2();

        let key1 = derive_key(&password, &salt, &argon2).unwrap();
        let key2 = derive_key(&password, &salt, &argon2).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_derive_key_different_salts() {
        let password = SecureString::new("test_password".to_string());
        let salt1 = [1u8; 16];
        let salt2 = [2u8; 16];
        let argon2 = create_test_argon2();

        let key1 = derive_key(&password, &salt1, &argon2).unwrap();
        let key2 = derive_key(&password, &salt2, &argon2).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_derive_filename_key_basic() {
        let master_key = SecureKey::new([42u8; 32]);

        let result = derive_filename_key(&master_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_filename_key_deterministic() {
        let master_key = SecureKey::new([42u8; 32]);

        let key1 = derive_filename_key(&master_key).unwrap();
        let key2 = derive_filename_key(&master_key).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_derive_filename_key_different_master() {
        let master_key1 = SecureKey::new([42u8; 32]);
        let master_key2 = SecureKey::new([43u8; 32]);

        let key1 = derive_filename_key(&master_key1).unwrap();
        let key2 = derive_filename_key(&master_key2).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
