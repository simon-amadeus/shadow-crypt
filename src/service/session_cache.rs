use crate::types::{KeyMaterial, SessionKey};
use base64::{Engine, engine::general_purpose};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Session key cache for performance optimization
pub struct SessionKeyCache {
    cache: Arc<RwLock<HashMap<String, SessionKey>>>,
    max_age: Duration,
}

impl SessionKeyCache {
    pub fn new(max_age: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            max_age,
        }
    }

    pub fn get_or_derive<F>(
        &self,
        password: &str,
        salt: &[u8],
        deriver: F,
    ) -> Result<KeyMaterial, crate::error::EncryptionError>
    where
        F: FnOnce(&str, &[u8]) -> Result<KeyMaterial, crate::error::EncryptionError>,
    {
        let cache_key = self.compute_cache_key(password, salt);

        // Try to get from cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(session_key) = cache.get(&cache_key) {
                if session_key.cache_until > Instant::now() {
                    return Ok(session_key.key_material.clone());
                }
            }
        }

        // Derive new key and cache it
        let key_material = deriver(password, salt)?;
        let session_key = SessionKey {
            key_material: key_material.clone(),
            salt: {
                let mut salt_array = [0u8; 16];
                salt_array.copy_from_slice(&salt[..16.min(salt.len())]);
                salt_array
            },
            cache_until: Instant::now() + self.max_age,
        };

        {
            let mut cache = self.cache.write().unwrap();
            cache.insert(cache_key, session_key);
        }

        Ok(key_material)
    }

    pub fn clear_expired(&self) {
        let mut cache = self.cache.write().unwrap();
        let now = Instant::now();
        cache.retain(|_, session_key| session_key.cache_until > now);
    }

    pub fn clear_all(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();
    }

    fn compute_cache_key(&self, password: &str, salt: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let hash = hasher.finalize();
        
        general_purpose::STANDARD.encode(&hash[..])
    }
}

impl Default for SessionKeyCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(300)) // 5 minutes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2KeyDeriver;
    use crate::traits::KeyDeriver;
    use secrecy::ExposeSecret;

    #[test]
    fn test_cache_hit_and_miss() {
        let cache = SessionKeyCache::new(Duration::from_secs(1));
        let deriver = Argon2KeyDeriver::new();
        let password = "test_password";
        let salt = [0u8; 16];

        // First call should miss cache and derive key
        let key1 = cache
            .get_or_derive(password, &salt, |p, s| deriver.derive_key(p, s))
            .unwrap();

        // Second call should hit cache
        let key2 = cache
            .get_or_derive(password, &salt, |p, s| deriver.derive_key(p, s))
            .unwrap();

        // Keys should be the same (from cache)
        assert_eq!(
            key1.encryption_key.expose_secret(),
            key2.encryption_key.expose_secret()
        );
    }

    #[test]
    fn test_cache_expiration() {
        let cache = SessionKeyCache::new(Duration::from_millis(10));
        let deriver = Argon2KeyDeriver::new();
        let password = "test_password";
        let salt = [0u8; 16];

        // First call
        let _key1 = cache
            .get_or_derive(password, &salt, |p, s| deriver.derive_key(p, s))
            .unwrap();

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        // This should miss cache due to expiration
        let _key2 = cache
            .get_or_derive(password, &salt, |p, s| deriver.derive_key(p, s))
            .unwrap();

        // Clear expired entries
        cache.clear_expired();
        
        // Cache should be empty now
        assert_eq!(cache.cache.read().unwrap().len(), 1); // Only the new entry
    }

    #[test]
    fn test_different_inputs_different_cache_keys() {
        let cache = SessionKeyCache::new(Duration::from_secs(60));
        let deriver = Argon2KeyDeriver::new();

        let password1 = "password1";
        let password2 = "password2";
        let salt = [0u8; 16];

        let _key1 = cache
            .get_or_derive(password1, &salt, |p, s| deriver.derive_key(p, s))
            .unwrap();

        let _key2 = cache
            .get_or_derive(password2, &salt, |p, s| deriver.derive_key(p, s))
            .unwrap();

        // Should have two different entries
        assert_eq!(cache.cache.read().unwrap().len(), 2);
    }
}
