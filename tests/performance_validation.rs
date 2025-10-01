//! Performance validation test
//! 
//! This test demonstrates that the Argon2 parameter optimization works correctly

#[cfg(test)]
mod performance_validation {
    use shadow_crypt::shared::algorithms::aes_gcm::{Argon2Params, derive_master_key, generate_salt};
    use std::time::Instant;
    
    #[test]
    fn test_fast_argon2_in_tests() {
        let start = Instant::now();
        
        // Integration tests need to explicitly use test parameters
        // since cfg!(test) doesn't work across compilation units
        let params = Argon2Params::test_params();
        assert_eq!(params.memory_cost, 1024, "Test should use 1MB memory");
        assert_eq!(params.time_cost, 1, "Test should use 1 iteration");
        assert_eq!(params.parallelism, 1, "Test should use 1 thread");
        
        // Test actual key derivation (should be fast)
        let password = "test_password";
        let salt = generate_salt(16).unwrap();
        let _key_material = derive_master_key(password, &salt, &params).unwrap();
        
        let duration = start.elapsed();
        println!("Key derivation took: {:?}", duration);
        
        // Should complete in well under 1 second with test parameters
        assert!(duration.as_secs() < 2, "Key derivation should be fast in tests: {:?}", duration);
    }
    
    #[test]
    fn test_production_parameters_are_secure() {
        // Test that production parameters are still secure
        let prod_params = Argon2Params::production_params();
        
        // Production should use more memory and time
        assert!(prod_params.memory_cost >= 32 * 1024, "Production should use at least 32MB");
        assert!(prod_params.time_cost >= 5, "Production should use at least 5 iterations");
        assert!(prod_params.parallelism >= 1, "Production should use at least 1 thread");
        
        println!("Production params: {}KB memory, {} iterations, {} threads", 
                 prod_params.memory_cost, prod_params.time_cost, prod_params.parallelism);
    }
}