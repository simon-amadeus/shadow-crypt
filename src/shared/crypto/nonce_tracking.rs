//! Nonce reuse detection for AES-GCM
//! 
//! AES-GCM has catastrophic security failure if nonces are reused with the same key.
//! This module provides runtime detection and prevention of nonce reuse.

use crate::shared::errors::CryptoError;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

/// Global nonce tracking for catastrophic failure prevention
/// 
/// This tracks nonces used during the current program execution to prevent
/// accidental reuse within the same session. This is a defense-in-depth measure
/// since nonces should be cryptographically random and practically never collide.
static USED_NONCES: OnceLock<Mutex<HashSet<[u8; 12]>>> = OnceLock::new();

fn get_nonce_tracker() -> &'static Mutex<HashSet<[u8; 12]>> {
    USED_NONCES.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Check if a nonce has been used before in this session
/// 
/// # Arguments
/// * `nonce` - 12-byte nonce to check
/// 
/// # Returns
/// * `Ok(())` - Nonce is safe to use (not seen before)
/// * `Err(CryptoError)` - CRITICAL: Nonce reuse detected
/// 
/// # Security Note
/// Nonce reuse with AES-GCM causes catastrophic security failure:
/// - Allows complete plaintext recovery
/// - Reveals authentication keys
/// - Breaks all security guarantees
pub fn check_nonce_reuse(nonce: &[u8; 12]) -> Result<(), CryptoError> {
    let mut used_nonces = get_nonce_tracker().lock()
        .map_err(|_| CryptoError::CryptographicError(
            "Failed to acquire nonce tracking lock".to_string()
        ))?;
    
    if used_nonces.contains(nonce) {
        return Err(CryptoError::CryptographicError(
            "CRITICAL: Nonce reuse detected! AES-GCM with repeated nonce causes catastrophic security failure".to_string()
        ));
    }
    
    used_nonces.insert(*nonce);
    Ok(())
}

/// Clear nonce tracking (for testing only)
/// 
/// # Security Warning
/// This should NEVER be called in production code except for clean shutdown.
/// Only use in tests to reset state between test runs.
#[cfg(test)]
pub fn clear_nonce_tracking() {
    if let Ok(mut used_nonces) = get_nonce_tracker().lock() {
        used_nonces.clear();
    }
}

/// Get statistics about nonce usage (for monitoring)
pub fn get_nonce_statistics() -> Result<usize, CryptoError> {
    let used_nonces = get_nonce_tracker().lock()
        .map_err(|_| CryptoError::CryptographicError(
            "Failed to acquire nonce tracking lock".to_string()
        ))?;
    
    Ok(used_nonces.len())
}

/// Validate nonce entropy and uniqueness properties
/// 
/// Performs basic statistical tests on nonce to detect obvious problems:
/// - All zeros (indicates generation failure)
/// - Low entropy patterns
/// - Common weak patterns
pub fn validate_nonce_entropy(nonce: &[u8; 12]) -> Result<(), CryptoError> {
    // Check for all-zero nonce (indicates RNG failure)
    if nonce.iter().all(|&b| b == 0) {
        return Err(CryptoError::CryptographicError(
            "CRITICAL: All-zero nonce detected - indicates random number generator failure".to_string()
        ));
    }
    
    // Check for all-same byte (indicates RNG failure)
    let first_byte = nonce[0];
    if nonce.iter().all(|&b| b == first_byte) {
        return Err(CryptoError::CryptographicError(
            format!("CRITICAL: Constant nonce pattern detected (all 0x{:02x}) - indicates RNG failure", first_byte)
        ));
    }
    
    // Check for ascending/descending patterns (indicates non-random generation)
    let is_ascending = nonce.windows(2).all(|w| w[1] >= w[0]);
    let is_descending = nonce.windows(2).all(|w| w[1] <= w[0]);
    
    if is_ascending || is_descending {
        return Err(CryptoError::CryptographicError(
            "CRITICAL: Sequential nonce pattern detected - indicates non-random generation".to_string()
        ));
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_nonce_reuse_detection() {
        clear_nonce_tracking();
        
        let nonce1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let nonce2 = [12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
        
        // First use should be fine
        assert!(check_nonce_reuse(&nonce1).is_ok());
        assert!(check_nonce_reuse(&nonce2).is_ok());
        
        // Reuse should be detected
        assert!(check_nonce_reuse(&nonce1).is_err());
        assert!(check_nonce_reuse(&nonce2).is_err());
        
        // Error messages should indicate critical nature
        let error = check_nonce_reuse(&nonce1).unwrap_err();
        assert!(error.to_string().contains("CRITICAL"));
        assert!(error.to_string().contains("catastrophic"));
    }
    
    #[test]
    fn test_nonce_statistics() {
        clear_nonce_tracking();
        
        assert_eq!(get_nonce_statistics().unwrap(), 0);
        
        let nonce1 = [1; 12];
        let nonce2 = [2; 12];
        
        // Note: These nonces will fail entropy validation, but we can still track them
        let _ = check_nonce_reuse(&nonce1);
        assert_eq!(get_nonce_statistics().unwrap(), 1);
        
        let _ = check_nonce_reuse(&nonce2);
        assert_eq!(get_nonce_statistics().unwrap(), 2);
    }
    
    #[test]
    fn test_validate_nonce_entropy_all_zeros() {
        let bad_nonce = [0u8; 12];
        let result = validate_nonce_entropy(&bad_nonce);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("All-zero nonce"));
    }
    
    #[test]
    fn test_validate_nonce_entropy_constant_pattern() {
        let bad_nonce = [0x42u8; 12];
        let result = validate_nonce_entropy(&bad_nonce);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Constant nonce pattern"));
    }
    
    #[test]
    fn test_validate_nonce_entropy_ascending_pattern() {
        let bad_nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let result = validate_nonce_entropy(&bad_nonce);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Sequential nonce pattern"));
    }
    
    #[test]
    fn test_validate_nonce_entropy_descending_pattern() {
        let bad_nonce = [11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
        let result = validate_nonce_entropy(&bad_nonce);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Sequential nonce pattern"));
    }
    
    #[test]
    fn test_validate_nonce_entropy_good_nonce() {
        let good_nonce = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x13, 0x57, 0x9b, 0xdf];
        let result = validate_nonce_entropy(&good_nonce);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_good_nonces_no_false_positives() {
        clear_nonce_tracking();
        
        // Generate some realistic random-looking nonces
        let good_nonces = [
            [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x13, 0x57, 0x9b, 0xdf],
            [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xfe, 0xdc, 0xba, 0x98],
            [0xff, 0x00, 0x55, 0xaa, 0x33, 0xcc, 0x77, 0x88, 0x11, 0x99, 0x22, 0x66],
        ];
        
        for nonce in &good_nonces {
            assert!(validate_nonce_entropy(nonce).is_ok(), "Good nonce rejected: {:?}", nonce);
            assert!(check_nonce_reuse(nonce).is_ok(), "Good nonce reuse detection failed: {:?}", nonce);
        }
    }
}