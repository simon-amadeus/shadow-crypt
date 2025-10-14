//! # Secure Key Material Entity
//!
//! Domain entity representing cryptographic key material and key derivation parameters
//! with secure memory management. This is a core security primitive that belongs in the
//! domain layer.

use super::memory::SecureBox;

/// Key derivation function parameters for password-based key derivation
/// 
/// KeyDerivationParams encapsulates the security parameters used for deriving
/// cryptographic keys from passwords. These parameters represent business rules
/// about acceptable security levels rather than implementation details.
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
    /// Create test parameters optimized for speed over security
    /// 
    /// These parameters should ONLY be used in test environments where
    /// cryptographic security is less important than execution speed.
    /// 
    /// # Security Warning
    /// These parameters provide minimal security and should never be used
    /// in production environments.
    pub fn test_argon2() -> Self {
        Self {
            memory_cost: 64,      // 64 KiB - minimal memory usage
            time_cost: 1,         // 1 iteration - minimal computation
            parallelism: 1,       // 1 thread - minimal resources
            output_length: 32,    // 32 bytes - sufficient for 256-bit keys
        }
    }

    /// Create production parameters optimized for security
    /// 
    /// These parameters follow current security best practices for Argon2id
    /// and provide strong resistance against brute-force attacks while
    /// maintaining reasonable performance on modern hardware.
    /// 
    /// # Security Properties
    /// - Memory cost: 1 GiB - maximum resistance against ASIC/GPU attacks
    /// - Time cost: 5 iterations - high security with acceptable performance
    /// - Parallelism: 4 threads - leverages multi-core processors efficiently
    /// - Output: 32 bytes - sufficient for 256-bit cryptographic keys
    /// 
    /// # Performance Note
    /// These parameters will consume ~1 GiB of RAM during key derivation
    /// and take 3-8 seconds on modern hardware. This provides maximum
    /// security for file encryption where strong protection is essential.
    pub fn production_argon2() -> Self {
        Self {
            memory_cost: 1048576, // 1 GiB - maximum practical security
            time_cost: 5,         // 5 iterations - high security level
            parallelism: 4,       // 4 threads - efficient on modern CPUs
            output_length: 32,    // 32 bytes - supports 256-bit algorithms
        }
    }

    /// Create custom parameters with validation
    /// 
    /// Validates that the provided parameters meet minimum security requirements
    /// for production use. This prevents accidentally creating weak configurations.
    /// 
    /// # Arguments
    /// * `memory_cost` - Memory usage in KiB (minimum 1024 for production)
    /// * `time_cost` - Iteration count (minimum 2 for production)
    /// * `parallelism` - Thread count (minimum 1, maximum 16)
    /// * `output_length` - Output size in bytes (minimum 16, maximum 64)
    /// 
    /// # Errors
    /// Returns error if any parameter is outside acceptable ranges
    pub fn custom(
        memory_cost: u32,
        time_cost: u32,
        parallelism: u32,
        output_length: usize,
    ) -> Result<Self, &'static str> {
        // Validate minimum security requirements
        if memory_cost < 262144 {
            return Err("Memory cost must be at least 256 MiB (262144 KiB) for production use");
        }
        if time_cost < 3 {
            return Err("Time cost must be at least 3 iterations for production use");
        }
        if parallelism == 0 || parallelism > 16 {
            return Err("Parallelism must be between 1 and 16 threads");
        }
        if output_length < 16 || output_length > 64 {
            return Err("Output length must be between 16 and 64 bytes");
        }

        Ok(Self {
            memory_cost,
            time_cost,
            parallelism,
            output_length,
        })
    }

    /// Check if parameters meet production security standards
    /// 
    /// Returns true if the parameters provide adequate security for production
    /// use based on current cryptographic best practices (2024+ standards).
    pub fn is_production_secure(&self) -> bool {
        self.memory_cost >= 1048576 &&  // At least 1 GiB (maximum security)
        self.time_cost >= 5 &&          // At least 5 iterations
        self.parallelism >= 1 &&        // At least 1 thread
        self.output_length >= 32        // At least 256-bit output
    }

    /// Get estimated derivation time in milliseconds
    /// 
    /// Provides a rough estimate of key derivation time based on the
    /// configured parameters. Actual time will vary based on hardware.
    /// 
    /// # Note
    /// This is an approximation based on typical modern hardware and
    /// should only be used for user experience planning, not security analysis.
    pub fn estimated_derivation_time_ms(&self) -> u64 {
        // Rough estimation based on empirical measurements
        // Memory cost has the largest impact on derivation time
        let base_time = (self.memory_cost / 1024) as u64; // ~1ms per MiB
        let iteration_multiplier = self.time_cost as u64;
        let parallelism_divisor = self.parallelism.max(1) as u64;
        
        (base_time * iteration_multiplier) / parallelism_divisor
    }
}

/// Key material container with automatic zeroization
/// 
/// KeyMaterial provides a secure container for cryptographic key data
/// that automatically zeroizes the key bytes when dropped. This follows
/// the patterns proven in the legacy implementation.
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
    /// Create new key material from derived keys
    /// 
    /// All provided keys will be moved into SecureBoxes and automatically
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

    /// Create key material from master key using key derivation
    /// 
    /// Derives encryption and obfuscation keys from the master key using
    /// secure key derivation function (KDF).
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

    /// Get total key material length (for compatibility with tests)
    /// 
    /// Returns the total number of bytes in all contained keys.
    pub fn len(&self) -> usize {
        // 32 bytes each for master_key, encryption_key, obfuscation_key
        96
    }

    /// Get encryption key bytes for cipher initialization
    /// 
    /// Returns a reference to the encryption key bytes. This method provides
    /// minimal necessary access to key material for cryptographic operations
    /// while maintaining security through SecureBox protection.
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