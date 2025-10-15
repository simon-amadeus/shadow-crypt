//! Cryptographic key material and derivation parameters.
//!
//! Secure containers for key material with automatic zeroization
//! and configurable key derivation parameters.

use super::memory::SecureBox;

/// Key derivation parameters for password-based key derivation.
/// 
/// Security parameters for deriving cryptographic keys from passwords
/// using Argon2id algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDerivationParams {
    /// Memory cost in KiB (affects memory usage during derivation)
    pub memory_cost: u32,
    /// Time cost in iterations (affects computation time during derivation)  
    pub time_cost: u32,
    /// Parallelism factor (number of threads used during derivation)
    pub parallelism: u32,
    /// Output key length in bytes
    pub output_length: usize,
}

impl KeyDerivationParams {
    // Security parameter constants
    
    /// Minimum memory cost for production use (1 GiB in KiB).
    pub const MIN_MEMORY_COST_PRODUCTION: u32 = 1_048_576; // 1 GiB
    
    /// Minimum memory cost for general use (256 MiB in KiB).
    pub const MIN_MEMORY_COST_GENERAL: u32 = 262_144; // 256 MiB
    
    /// Minimum time cost for production use.
    pub const MIN_TIME_COST_PRODUCTION: u32 = 5;
    
    /// Minimum time cost for general use.
    pub const MIN_TIME_COST_GENERAL: u32 = 3;
    
    /// Maximum parallelism (thread count).
    pub const MAX_PARALLELISM: u32 = 16;
    
    /// Minimum output length in bytes.
    pub const MIN_OUTPUT_LENGTH: usize = 16;
    
    /// Maximum output length in bytes.  
    pub const MAX_OUTPUT_LENGTH: usize = 64;
    
    /// Recommended output length for production (256-bit keys).
    pub const RECOMMENDED_OUTPUT_LENGTH: usize = 32;
}

impl KeyDerivationParams {
    /// Create test parameters optimized for speed.
    /// 
    /// These parameters should ONLY be used in test environments.
    /// Provides minimal security in favor of execution speed.
    pub fn test_argon2() -> Self {
        Self {
            memory_cost: 64,      // 64 KiB - minimal memory usage
            time_cost: 1,         // 1 iteration - minimal computation
            parallelism: 1,       // 1 thread - minimal resources
            output_length: 32,    // 32 bytes - sufficient for 256-bit keys
        }
    }

    /// Create production parameters optimized for security.
    /// 
    /// Provides strong resistance against brute-force attacks while
    /// maintaining reasonable performance on modern hardware.
    pub fn production_argon2() -> Self {
        Self {
            memory_cost: Self::MIN_MEMORY_COST_PRODUCTION,
            time_cost: Self::MIN_TIME_COST_PRODUCTION,
            parallelism: 4,
            output_length: Self::RECOMMENDED_OUTPUT_LENGTH,
        }
    }

    /// Create custom parameters with validation.
    /// 
    /// Validates that parameters meet minimum security requirements.
    /// 
    /// # Arguments
    /// * `memory_cost` - Memory usage in KiB (minimum 1024)
    /// * `time_cost` - Iteration count (minimum 2)
    /// * `parallelism` - Thread count (minimum 1, maximum 16)
    /// * `output_length` - Output size in bytes (minimum 16, maximum 64)
    pub fn custom(
        memory_cost: u32,
        time_cost: u32,
        parallelism: u32,
        output_length: usize,
    ) -> Result<Self, &'static str> {
        // Validate minimum security requirements
        if memory_cost < Self::MIN_MEMORY_COST_GENERAL {
            return Err("Memory cost must be at least 256 MiB (262144 KiB) for general use");
        }
        if time_cost < Self::MIN_TIME_COST_GENERAL {
            return Err("Time cost must be at least 3 iterations for general use");
        }
        if parallelism == 0 || parallelism > Self::MAX_PARALLELISM {
            return Err("Parallelism must be between 1 and 16 threads");
        }
        if output_length < Self::MIN_OUTPUT_LENGTH || output_length > Self::MAX_OUTPUT_LENGTH {
            return Err("Output length must be between 16 and 64 bytes");
        }

        Ok(Self {
            memory_cost,
            time_cost,
            parallelism,
            output_length,
        })
    }

    /// Check if parameters meet production security standards.
    pub fn is_production_secure(&self) -> bool {
        self.memory_cost >= Self::MIN_MEMORY_COST_PRODUCTION &&  // At least 1 GiB (maximum security)
        self.time_cost >= Self::MIN_TIME_COST_PRODUCTION &&      // At least 5 iterations
        self.parallelism >= 1 &&                                // At least 1 thread
        self.output_length >= Self::RECOMMENDED_OUTPUT_LENGTH    // At least 256-bit output
    }

    /// Get estimated derivation time in milliseconds.
    /// 
    /// Rough estimate based on typical hardware. Actual time varies.
    pub fn estimated_derivation_time_ms(&self) -> u64 {
        // Rough estimation based on empirical measurements
        // Memory cost has the largest impact on derivation time
        let base_time = (self.memory_cost / 1024) as u64; // ~1ms per MiB
        let iteration_multiplier = self.time_cost as u64;
        let parallelism_divisor = self.parallelism.max(1) as u64;
        
        (base_time * iteration_multiplier) / parallelism_divisor
    }
}

/// Key material container with automatic zeroization.
/// 
/// Secure container for cryptographic key data that automatically
/// zeroizes key bytes when dropped.
#[derive(Debug)]
pub struct KeyMaterial {
    /// Master key derived from password and salt
    pub master_key: SecureBox<[u8; 32]>,
    /// Key used for file encryption/decryption  
    pub encryption_key: SecureBox<[u8; 32]>,
    /// Key used for filename obfuscation
    pub obfuscation_key: SecureBox<[u8; 32]>,
}

impl PartialEq for KeyMaterial {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        
        self.master_key.expose_secret().ct_eq(other.master_key.expose_secret()).into() &&
        self.encryption_key.expose_secret().ct_eq(other.encryption_key.expose_secret()).into() &&
        self.obfuscation_key.expose_secret().ct_eq(other.obfuscation_key.expose_secret()).into()
    }
}

impl Eq for KeyMaterial {}

impl KeyMaterial {
    /// Create new key material from derived keys.
    /// 
    /// All keys are moved into SecureBoxes and automatically
    /// zeroized when the KeyMaterial is dropped.
    pub fn new(
        master_key: [u8; 32],
        encryption_key: [u8; 32], 
        obfuscation_key: [u8; 32],
    ) -> Self {
        Self {
            master_key: SecureBox::new(master_key),
            encryption_key: SecureBox::new(encryption_key),
            obfuscation_key: SecureBox::new(obfuscation_key),
        }
    }

    /// Create key material from master key using key derivation.
    /// 
    /// Derives encryption and obfuscation keys from the master key.
    pub fn from_master_key(master_key: [u8; 32]) -> Self {
        // Use HKDF to derive separate keys from master key
        use sha2::Sha256;
        use hkdf::Hkdf;
        
        let hkdf = Hkdf::<Sha256>::new(None, &master_key);
        
        let mut encryption_key = [0u8; 32];
        let mut obfuscation_key = [0u8; 32];
        
        hkdf.expand(b"encryption", &mut encryption_key)
            .expect("HKDF encryption key derivation should not fail");
        hkdf.expand(b"obfuscation", &mut obfuscation_key)
            .expect("HKDF obfuscation key derivation should not fail");
        
        Self::new(master_key, encryption_key, obfuscation_key)
    }

    /// Get total key material length.
    pub fn len(&self) -> usize {
        // 32 bytes each for master_key, encryption_key, obfuscation_key
        96
    }

    /// Get encryption key bytes for cipher initialization.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.encryption_key.expose_secret()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_params_test_config() {
        let params = KeyDerivationParams::test_argon2();
        assert_eq!(params.memory_cost, 64);
        assert_eq!(params.time_cost, 1);
        assert_eq!(params.parallelism, 1);
        assert_eq!(params.output_length, 32);
        assert!(!params.is_production_secure());
    }

    #[test]
    fn test_key_derivation_params_production_config() {
        let params = KeyDerivationParams::production_argon2();
        assert_eq!(params.memory_cost, 1048576); // 1 GiB
        assert_eq!(params.time_cost, 5);
        assert_eq!(params.parallelism, 4);
        assert_eq!(params.output_length, 32);
        assert!(params.is_production_secure());
    }

    #[test]
    fn test_key_derivation_params_custom_validation() {
        // Valid parameters
        let valid = KeyDerivationParams::custom(1048576, 5, 2, 32); // 1 GiB, 5 iterations
        assert!(valid.is_ok());
        assert!(valid.unwrap().is_production_secure());

        // Invalid parameters
        assert!(KeyDerivationParams::custom(131072, 5, 2, 32).is_err()); // Below 256 MiB minimum
        assert!(KeyDerivationParams::custom(1048576, 2, 2, 32).is_err()); // Low iterations (below 3)
        assert!(KeyDerivationParams::custom(1048576, 5, 0, 32).is_err()); // Zero parallelism
        assert!(KeyDerivationParams::custom(1048576, 5, 2, 8).is_err());  // Small output
    }

    #[test]
    fn test_estimated_derivation_time() {
        let test_params = KeyDerivationParams::test_argon2();
        let production_params = KeyDerivationParams::production_argon2();
        
        // Production should take longer than test
        assert!(production_params.estimated_derivation_time_ms() > 
                test_params.estimated_derivation_time_ms());
        
        // Test should be very fast
        assert!(test_params.estimated_derivation_time_ms() < 10);
    }

    #[test]
    fn test_key_material_creation() {
        let master = [1u8; 32];
        let encryption = [2u8; 32];
        let obfuscation = [3u8; 32];
        
        let key_material = KeyMaterial::new(master, encryption, obfuscation);
        assert_eq!(key_material.len(), 96);
        assert_eq!(key_material.as_bytes(), &[2u8; 32]);
    }

    #[test]
    fn test_key_material_from_master_key() {
        let master = [42u8; 32];
        let key_material = KeyMaterial::from_master_key(master);
        
        assert_eq!(key_material.len(), 96);
        assert_eq!(key_material.master_key.expose_secret(), &master);
        
        // Derived keys should be different from master key
        assert_ne!(key_material.encryption_key.expose_secret(), &master);
        assert_ne!(key_material.obfuscation_key.expose_secret(), &master);
        
        // Derived keys should be different from each other
        assert_ne!(
            key_material.encryption_key.expose_secret(),
            key_material.obfuscation_key.expose_secret()
        );
    }

    #[test]
    fn test_key_material_equality() {
        let master = [1u8; 32];
        let key1 = KeyMaterial::from_master_key(master);
        let key2 = KeyMaterial::from_master_key(master);
        let key3 = KeyMaterial::from_master_key([2u8; 32]);
        
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }
}