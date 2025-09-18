use crate::error::EncryptionError;
use crate::traits::KeyDeriver;
use crate::types::{KeyMaterial, SessionKey};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString};
use base64::{Engine, engine::general_purpose};
use std::time::{Duration, Instant};

/// Argon2-based key derivation implementation
pub struct Argon2KeyDeriver {
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    session_cache_duration: Duration,
}

impl Argon2KeyDeriver {
    pub fn new() -> Self {
        Self {
            memory_cost: 65536, // 64 MiB
            time_cost: 3,
            parallelism: 4,
            session_cache_duration: Duration::from_secs(300), // 5 minutes
        }
    }

    pub fn with_params(memory_cost: u32, time_cost: u32, parallelism: u32) -> Self {
        Self {
            memory_cost,
            time_cost,
            parallelism,
            session_cache_duration: Duration::from_secs(300),
        }
    }

    fn derive_key_material(&self, password: &str, salt: &[u8]) -> Result<KeyMaterial, EncryptionError> {
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                self.memory_cost,
                self.time_cost,
                self.parallelism,
                Some(96), // 3 * 32 bytes for our three keys
            ).map_err(|e| EncryptionError::KeyDerivationError(e.to_string()))?,
        );

        let salt_string = SaltString::from_b64(
            &general_purpose::STANDARD.encode(salt)
        ).map_err(|e| EncryptionError::KeyDerivationError(e.to_string()))?;

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| EncryptionError::KeyDerivationError(e.to_string()))?;

        let hash_output = password_hash.hash.ok_or_else(|| {
            EncryptionError::KeyDerivationError("No hash output".to_string())
        })?;
        let hash_bytes = hash_output.as_bytes();
        
        if hash_bytes.len() < 96 {
            return Err(EncryptionError::KeyDerivationError(
                "Insufficient key material derived".to_string()
            ));
        }

        let mut encryption_key = [0u8; 32];
        let mut hmac_key = [0u8; 32];
        let mut obfuscation_key = [0u8; 32];

        encryption_key.copy_from_slice(&hash_bytes[0..32]);
        hmac_key.copy_from_slice(&hash_bytes[32..64]);
        obfuscation_key.copy_from_slice(&hash_bytes[64..96]);

        Ok(KeyMaterial::new(encryption_key, hmac_key, obfuscation_key))
    }
}

impl Default for Argon2KeyDeriver {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyDeriver for Argon2KeyDeriver {
    fn derive_key(&self, password: &str, salt: &[u8]) -> Result<KeyMaterial, EncryptionError> {
        if salt.len() != 16 {
            return Err(EncryptionError::KeyDerivationError(
                "Salt must be exactly 16 bytes".to_string()
            ));
        }

        self.derive_key_material(password, salt)
    }

    fn derive_session_key(&self, password: &str) -> Result<SessionKey, EncryptionError> {
        use rand::RngCore;
        
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        
        let key_material = self.derive_key_material(password, &salt)?;
        
        Ok(SessionKey {
            key_material,
            salt,
            cache_until: Instant::now() + self.session_cache_duration,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_key_derivation() {
        let deriver = Argon2KeyDeriver::new();
        let salt = [0u8; 16];
        let password = "test_password";

        let key1 = deriver.derive_key(password, &salt).unwrap();
        let key2 = deriver.derive_key(password, &salt).unwrap();

        // Keys should be deterministic for same input
        assert_eq!(
            key1.encryption_key.expose_secret(),
            key2.encryption_key.expose_secret()
        );
    }

    #[test]
    fn test_different_salts_produce_different_keys() {
        let deriver = Argon2KeyDeriver::new();
        let salt1 = [0u8; 16];
        let salt2 = [1u8; 16];
        let password = "test_password";

        let key1 = deriver.derive_key(password, &salt1).unwrap();
        let key2 = deriver.derive_key(password, &salt2).unwrap();

        assert_ne!(
            key1.encryption_key.expose_secret(),
            key2.encryption_key.expose_secret()
        );
    }

    #[test]
    fn test_session_key_generation() {
        let deriver = Argon2KeyDeriver::new();
        let password = "test_password";

        let session_key = deriver.derive_session_key(password).unwrap();
        
        assert!(session_key.cache_until > Instant::now());
        assert_eq!(session_key.salt.len(), 16);
    }
}
