//! Security improvements validation tests
//! 
//! This module validates the security improvements implemented in Phase 9.5

#[cfg(test)]
mod security_validation_tests {
    use shadow_crypt::shared::algorithms::{AesGcmConfig, CryptoConfig};
    use shadow_crypt::shared::algorithms::aes_gcm::{derive_master_key, generate_salt};
    use shadow_crypt::encryption::filename_obfuscation::{obfuscate_filename, verify_obfuscated_filename};
    
    #[test]
    fn test_adaptive_argon2_parameters() {
        // Test production parameters (what would be used in real deployment)
        let config = AesGcmConfig::production_config();
        let params = config.argon2_params();
        
        // Memory cost should be reasonable (32MB to 512MB range)
        assert!(params.memory_cost >= 32 * 1024, "Memory cost too low: {}", params.memory_cost);
        assert!(params.memory_cost <= 512 * 1024, "Memory cost too high: {}", params.memory_cost);
        
        // Parallelism should be between 1 and 8
        assert!(params.parallelism >= 1, "Parallelism too low: {}", params.parallelism);
        assert!(params.parallelism <= 8, "Parallelism too high: {}", params.parallelism);
        
        // Time cost should be secure (minimum 5)
        assert!(params.time_cost >= 5, "Time cost too low: {}", params.time_cost);
        
        println!("Production Argon2 params - Memory: {}KB, Time: {}, Parallelism: {}", 
                 params.memory_cost, params.time_cost, params.parallelism);
                 
        // Test that test parameters are lightweight
        let test_config = AesGcmConfig::test_config();
        let test_params = test_config.argon2_params();
        assert_eq!(test_params.memory_cost, 1024, "Test memory cost should be 1MB");
        assert_eq!(test_params.time_cost, 1, "Test time cost should be 1");
        assert_eq!(test_params.parallelism, 1, "Test parallelism should be 1");
        
        println!("Test Argon2 params - Memory: {}KB, Time: {}, Parallelism: {}", 
                 test_params.memory_cost, test_params.time_cost, test_params.parallelism);
        
        // Test that we can explicitly get both parameter types
        let default_config = AesGcmConfig::production_config();
        let default_params = default_config.argon2_params();
        // In integration tests, default uses production params, which is correct
        // We just verify that test params are available when explicitly requested
        assert_eq!(test_params.memory_cost, 1024);
        assert_eq!(test_params.time_cost, 1);
        assert_eq!(test_params.parallelism, 1);
        
        // Verify production params are reasonable
        assert!(default_params.memory_cost >= 32 * 1024);
        assert!(default_params.memory_cost <= 512 * 1024);
    }
    
    #[test]
    fn test_system_resource_detection() {
        // Test that production parameters are based on actual system resources
        let config1 = AesGcmConfig::production_config();
        let config2 = AesGcmConfig::production_config();
        let params1 = config1.argon2_params();
        let params2 = config2.argon2_params();
        
        // Parameters should be consistent (deterministic based on system)
        assert_eq!(params1.memory_cost, params2.memory_cost);
        assert_eq!(params1.parallelism, params2.parallelism);
        
        // Test that we can get custom parameters
        let custom_config = AesGcmConfig::with_params(2048, 3, 2);
        let custom = custom_config.argon2_params();
        assert_eq!(custom.memory_cost, 2048);
        assert_eq!(custom.time_cost, 3);
        assert_eq!(custom.parallelism, 2);
    }
    
    #[test]
    fn test_constant_time_verification() {
        let key = [0u8; 32];
        let filename = "test_timing.txt";
        
        // Create obfuscated filename
        let obfuscated = obfuscate_filename(&key, filename).unwrap();
        
        // Test that verification works with correct filename
        assert!(verify_obfuscated_filename(&key, filename, &obfuscated).unwrap());
        
        // Test that verification fails with incorrect filename
        assert!(!verify_obfuscated_filename(&key, "wrong.txt", &obfuscated).unwrap());
        
        // Note: Constant-time behavior is hard to test in unit tests
        // This would require specialized timing attack testing tools
        println!("Constant-time verification test passed");
    }
    
    #[test]
    fn test_key_derivation_with_adaptive_params() {
        // Test that key derivation works with test parameters (fast)
        let password = "test_password";
        let salt = generate_salt(16).unwrap();
        let config = AesGcmConfig::test_config();
        let params = config.argon2_params(); // Use fast test params
        
        let key_material = derive_master_key(password, &salt, params).unwrap();
        
        // Verify we get proper key material
        assert_eq!(key_material.master_key.len(), 32);
        assert_eq!(key_material.encryption_key.len(), 32);
        assert_eq!(key_material.obfuscation_key.len(), 32);
        
        println!("Fast key derivation test passed");
    }
    
    #[test]
    fn test_memory_bounds_enforcement() {
        // Test that production memory cost has reasonable bounds
        let config = AesGcmConfig::production_config();
        let params = config.argon2_params();
        
        // Should never use less than 32MB (secure minimum)
        assert!(params.memory_cost >= 32 * 1024);
        
        // Should never use more than 512MB (usability maximum)
        assert!(params.memory_cost <= 512 * 1024);
        
        // Test that test parameters are fast
        let test_config = AesGcmConfig::test_config();
        let test_params = test_config.argon2_params();
        assert_eq!(test_params.memory_cost, 1024); // 1MB for fast testing
        
        println!("Memory bounds enforcement test passed");
    }
}