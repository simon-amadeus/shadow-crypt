//! Pure cryptographic operations for the functional pipeline.

use super::types::{AlgorithmId, KeyMaterial, KeyDerivationParams};
use super::session::CryptoSession;
use crate::core::types::{CoreResult, CryptoError};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;

/// Pure function to derive key material from password.
pub fn derive_key_material(
    password: &str,
    salt: &[u8],
    params: &KeyDerivationParams,
    algorithm: AlgorithmId,
) -> CoreResult<KeyMaterial> {
    // Create Argon2 instance with specified parameters
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            params.memory_cost,
            params.time_cost,
            params.parallelism,
            Some(64), // Maximum output length
        ).map_err(|e| CryptoError::KeyDerivation { 
            reason: format!("Invalid Argon2 parameters: {}", e) 
        })?,
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

/// Pure function to create a crypto session from password.
pub fn create_session(
    password: &str,
    algorithm: AlgorithmId,
    params: Option<KeyDerivationParams>,
) -> CoreResult<CryptoSession> {
    let params = params.unwrap_or_else(KeyDerivationParams::general);
    
    // Generate random salt
    let mut salt = [0u8; 32];
    use rand::RngCore;
    let mut rng = rand::rng();
    rng.fill_bytes(&mut salt);
    
    // Derive key material
    let key_material = derive_key_material(password, &salt, &params, algorithm)?;
    
    Ok(CryptoSession::new(key_material, salt, algorithm))
}

/// Pure function to generate a random nonce for the given algorithm.
pub fn generate_nonce(algorithm: AlgorithmId) -> CoreResult<Vec<u8>> {
    let nonce_size = algorithm.nonce_size();
    let mut nonce = vec![0u8; nonce_size];
    
    use rand::RngCore;
    let mut rng = rand::rng();
    rng.fill_bytes(&mut nonce);
    
    Ok(nonce)
}