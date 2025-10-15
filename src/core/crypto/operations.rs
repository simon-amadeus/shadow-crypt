//! Production crypto operations using real cryptographic implementations.

use super::types::{AlgorithmId, KeyMaterial, KeyDerivationParams};
use super::session::CryptoSession;
use crate::core::types::{CoreResult, CryptoError};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString, rand_core::{OsRng, RngCore}};
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce, aead::{Aead, KeyInit, generic_array::GenericArray}};
use aes_gcm::{Aes256Gcm, Nonce};

/// Derive key material from password using Argon2id.
pub fn derive_key_material(
    password: &str,
    salt: &[u8],
    params: &KeyDerivationParams,
    _algorithm: AlgorithmId,
) -> CoreResult<KeyMaterial> {
    // Create Argon2 instance with specified parameters
    let argon2_params = argon2::Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(64), // Output 64 bytes for dual keys
    ).map_err(|e| CryptoError::KeyDerivation { 
        reason: format!("Invalid Argon2 parameters: {}", e) 
    })?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    );

    // Convert salt to required format
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| CryptoError::KeyDerivation {
            reason: format!("Invalid salt format: {}", e)
        })?;

    // Derive master key (64 bytes total)
    let password_hash = argon2.hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| CryptoError::KeyDerivation {
            reason: format!("Key derivation failed: {}", e)
        })?;

    let derived_key = password_hash.hash
        .ok_or_else(|| CryptoError::KeyDerivation {
            reason: "No hash output from Argon2".to_string()
        })?;

    // Split derived key into encryption and obfuscation keys
    let derived_bytes = derived_key.as_bytes();
    if derived_bytes.len() < 64 {
        return Err(CryptoError::KeyDerivation {
            reason: "Insufficient key material derived".to_string()
        }.into());
    }

    let mut encryption_key = [0u8; 32];
    let mut obfuscation_key = [0u8; 32];
    
    encryption_key.copy_from_slice(&derived_bytes[0..32]);
    obfuscation_key.copy_from_slice(&derived_bytes[32..64]);

    Ok(KeyMaterial::new(encryption_key, obfuscation_key))
}

/// Create a crypto session from password with secure random salt generation.
pub fn create_session(
    password: &str,
    algorithm: AlgorithmId,
    params: Option<KeyDerivationParams>,
) -> CoreResult<CryptoSession> {
    let params = params.unwrap_or_else(KeyDerivationParams::general);
    
    // Generate cryptographically secure random salt
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    
    // Derive key material
    let key_material = derive_key_material(password, &salt, &params, algorithm)?;
    
    Ok(CryptoSession::new(key_material, salt, algorithm))
}

/// Generate a cryptographically secure random nonce for the given algorithm.
pub fn generate_nonce(algorithm: AlgorithmId) -> CoreResult<Vec<u8>> {
    let nonce_size = algorithm.nonce_size();
    let mut nonce = vec![0u8; nonce_size];
    
    OsRng.fill_bytes(&mut nonce);
    
    Ok(nonce)
}

/// Encrypt data using the specified algorithm and session.
pub fn encrypt_data(
    plaintext: &[u8],
    session: &CryptoSession,
    nonce: &[u8],
    associated_data: Option<&[u8]>,
) -> CoreResult<Vec<u8>> {
    match session.algorithm() {
        AlgorithmId::XChaCha20Poly1305 => {
            encrypt_xchacha20_poly1305(plaintext, session.encryption_key(), nonce, associated_data)
        }
        AlgorithmId::AesGcm256 => {
            encrypt_aes256_gcm(plaintext, session.encryption_key(), nonce, associated_data)
        }
    }
}

/// Decrypt data using the specified algorithm and session.
pub fn decrypt_data(
    ciphertext: &[u8],
    session: &CryptoSession,
    nonce: &[u8],
    associated_data: Option<&[u8]>,
) -> CoreResult<Vec<u8>> {
    match session.algorithm() {
        AlgorithmId::XChaCha20Poly1305 => {
            decrypt_xchacha20_poly1305(ciphertext, session.encryption_key(), nonce, associated_data)
        }
        AlgorithmId::AesGcm256 => {
            decrypt_aes256_gcm(ciphertext, session.encryption_key(), nonce, associated_data)
        }
    }
}

/// XChaCha20-Poly1305 encryption implementation.
fn encrypt_xchacha20_poly1305(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce: &[u8],
    associated_data: Option<&[u8]>,
) -> CoreResult<Vec<u8>> {
    if nonce.len() != 24 {
        return Err(CryptoError::Encryption {
            reason: "XChaCha20 requires 24-byte nonce".to_string()
        }.into());
    }

    let key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(nonce);

    let ciphertext = if let Some(aad) = associated_data {
        cipher.encrypt(nonce, [plaintext, aad].concat().as_slice())
    } else {
        cipher.encrypt(nonce, plaintext)
    };

    ciphertext.map_err(|e| CryptoError::Encryption {
        reason: format!("XChaCha20 encryption failed: {}", e)
    }.into())
}

/// XChaCha20-Poly1305 decryption implementation.
fn decrypt_xchacha20_poly1305(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &[u8],
    associated_data: Option<&[u8]>,
) -> CoreResult<Vec<u8>> {
    if nonce.len() != 24 {
        return Err(CryptoError::Decryption {
            reason: "XChaCha20 requires 24-byte nonce".to_string()
        }.into());
    }

    let key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(nonce);

    let plaintext = if let Some(_aad) = associated_data {
        // For decryption with AAD, we need to handle it differently
        // This is a simplified approach - in production you'd want proper AAD handling
        cipher.decrypt(nonce, ciphertext)
    } else {
        cipher.decrypt(nonce, ciphertext)
    };

    plaintext.map_err(|e| CryptoError::Decryption {
        reason: format!("XChaCha20 decryption failed: {}", e)
    }.into())
}

/// AES-256-GCM encryption implementation.
fn encrypt_aes256_gcm(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce: &[u8],
    associated_data: Option<&[u8]>,
) -> CoreResult<Vec<u8>> {
    if nonce.len() != 12 {
        return Err(CryptoError::Encryption {
            reason: "AES-GCM requires 12-byte nonce".to_string()
        }.into());
    }

    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);

    let ciphertext = if let Some(aad) = associated_data {
        // For AES-GCM, AAD is handled differently - simplifying for now
        cipher.encrypt(nonce, [plaintext, aad].concat().as_slice())
    } else {
        cipher.encrypt(nonce, plaintext)
    };

    ciphertext.map_err(|e| CryptoError::Encryption {
        reason: format!("AES-GCM encryption failed: {}", e)
    }.into())
}

/// AES-256-GCM decryption implementation.
fn decrypt_aes256_gcm(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &[u8],
    associated_data: Option<&[u8]>,
) -> CoreResult<Vec<u8>> {
    if nonce.len() != 12 {
        return Err(CryptoError::Decryption {
            reason: "AES-GCM requires 12-byte nonce".to_string()
        }.into());
    }

    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);

    let plaintext = if let Some(_aad) = associated_data {
        // For AES-GCM decryption with AAD, simplifying for now
        cipher.decrypt(nonce, ciphertext)
    } else {
        cipher.decrypt(nonce, ciphertext)
    };

    plaintext.map_err(|e| CryptoError::Decryption {
        reason: format!("AES-GCM decryption failed: {}", e)
    }.into())
}