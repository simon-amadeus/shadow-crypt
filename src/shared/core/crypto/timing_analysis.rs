//! Timing attack detection and prevention
//! 
//! This module provides statistical analysis of cryptographic operations
//! to detect timing vulnerabilities that could leak sensitive information.

use crate::shared::errors::CryptoError;
use std::time::{Duration, Instant};

/// Statistical analysis for timing attack detection
#[derive(Debug)]
pub struct TimingAnalyzer {
    samples: Vec<Duration>,
    operation_name: String,
}

impl TimingAnalyzer {
    /// Create a new timing analyzer for a specific operation
    pub fn new(operation_name: &str) -> Self {
        Self {
            samples: Vec::new(),
            operation_name: operation_name.to_string(),
        }
    }
    
    /// Measure timing of a cryptographic operation
    pub fn measure<F, R>(&mut self, operation: F) -> R 
    where 
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = operation();
        let duration = start.elapsed();
        self.samples.push(duration);
        result
    }
    
    /// Add a pre-measured sample
    pub fn add_sample(&mut self, duration: Duration) {
        self.samples.push(duration);
    }
    
    /// Perform statistical analysis to detect timing vulnerabilities
    pub fn analyze_timing_security(&self) -> Result<TimingAnalysisResult, CryptoError> {
        if self.samples.len() < 10 {
            return Err(CryptoError::CryptographicError(
                "Insufficient samples for timing analysis (minimum 10 required)".to_string()
            ));
        }
        
        let mean = self.calculate_mean();
        let variance = self.calculate_variance(mean);
        let std_dev = variance.sqrt();
        let coefficient_of_variation = std_dev / mean;
        
        let min_time = self.samples.iter().min().unwrap();
        let max_time = self.samples.iter().max().unwrap();
        let range_ratio = max_time.as_nanos() as f64 / min_time.as_nanos() as f64;
        
        // Detect potential timing vulnerabilities
        let mut vulnerabilities = Vec::new();
        
        // For cryptographic operations, some timing variation is expected
        // We look for more significant variations that could indicate vulnerabilities
        if coefficient_of_variation > 0.3 {
            vulnerabilities.push(format!(
                "High timing variation detected (CV: {:.3}) - may indicate timing attack vulnerability",
                coefficient_of_variation
            ));
        }
        
        // Large time range differences may indicate input-dependent timing
        // For same-size operations, this should be smaller
        if range_ratio > 5.0 {
            vulnerabilities.push(format!(
                "Large timing range detected (max/min ratio: {:.2}) - may indicate input-dependent timing",
                range_ratio
            ));
        }
        
        // Suspiciously consistent timing might indicate padding
        if coefficient_of_variation < 0.001 && self.samples.len() > 100 {
            vulnerabilities.push(
                "Timing is suspiciously consistent - verify this is genuine constant-time behavior".to_string()
            );
        }
        
        Ok(TimingAnalysisResult {
            operation_name: self.operation_name.clone(),
            sample_count: self.samples.len(),
            mean_time: Duration::from_nanos(mean as u64),
            std_deviation: Duration::from_nanos(std_dev as u64),
            min_time: *min_time,
            max_time: *max_time,
            coefficient_of_variation,
            range_ratio,
            vulnerabilities,
        })
    }
    
    /// Calculate mean timing
    fn calculate_mean(&self) -> f64 {
        let sum: u128 = self.samples.iter().map(|d| d.as_nanos()).sum();
        sum as f64 / self.samples.len() as f64
    }
    
    /// Calculate variance
    fn calculate_variance(&self, mean: f64) -> f64 {
        let sum_squares: f64 = self.samples.iter()
            .map(|d| {
                let diff = d.as_nanos() as f64 - mean;
                diff * diff
            })
            .sum();
        sum_squares / self.samples.len() as f64
    }
    
    /// Clear all samples (for reuse)
    pub fn clear(&mut self) {
        self.samples.clear();
    }
}

/// Result of timing analysis
#[derive(Debug)]
pub struct TimingAnalysisResult {
    pub operation_name: String,
    pub sample_count: usize,
    pub mean_time: Duration,
    pub std_deviation: Duration,
    pub min_time: Duration,
    pub max_time: Duration,
    pub coefficient_of_variation: f64,
    pub range_ratio: f64,
    pub vulnerabilities: Vec<String>,
}

impl TimingAnalysisResult {
    /// Check if timing analysis indicates potential security issues
    pub fn has_timing_vulnerabilities(&self) -> bool {
        !self.vulnerabilities.is_empty()
    }
    
    /// Get security assessment
    pub fn security_assessment(&self) -> String {
        if self.vulnerabilities.is_empty() {
            format!("✅ No timing vulnerabilities detected in '{}' operation", self.operation_name)
        } else {
            format!("⚠️  Potential timing vulnerabilities in '{}' operation:\n{}", 
                   self.operation_name,
                   self.vulnerabilities.join("\n"))
        }
    }
}

/// Test password validation timing for constant-time behavior
pub fn test_password_validation_timing() -> Result<TimingAnalysisResult, CryptoError> {
    use crate::shared::crypto::{derive_master_key, generate_salt, Argon2Params};
    
    let mut analyzer = TimingAnalyzer::new("password_validation");
    let salt = generate_salt(16)?;
    let params = Argon2Params::test_params(); // Use fast params for timing test
    
    // Test with various password lengths and complexities
    let repeated_a = "a".repeat(100);
    let test_passwords = [
        "short",
        "medium_length_password",
        "very_long_password_with_many_characters_to_test_timing",
        "unicode_测试_пароль_🔐",
        "special!@#$%^&*()_+-={}[]|\\:;\"'<>?,.password",
        repeated_a.as_str(),
    ];
    
    // Measure timing for each password multiple times
    for _ in 0..5 {
        for password in &test_passwords {
            analyzer.measure(|| {
                derive_master_key(password, &salt, &params)
            })?;
        }
    }
    
    analyzer.analyze_timing_security()
}

/// Test AES-GCM encryption timing for constant-time behavior
pub fn test_aes_gcm_timing() -> Result<TimingAnalysisResult, CryptoError> {
    use crate::shared::crypto::{encrypt_aes_gcm, generate_random_key, generate_secure_nonce};
    
    let mut analyzer = TimingAnalyzer::new("aes_gcm_encryption_same_size");
    let key = generate_random_key()?;
    
    // Test with same-size data but different patterns to detect pattern-dependent timing
    // (Size-dependent timing is expected and not a vulnerability)
    let data_size = 1024;
    let test_data: Vec<Vec<u8>> = vec![
        vec![0u8; data_size],           // All zeros
        vec![0xFFu8; data_size],        // All ones
        vec![0xAAu8; data_size],        // Alternating pattern
        vec![0x55u8; data_size],        // Alternating pattern
        (0..data_size).map(|i| i as u8).collect(), // Sequential pattern
        (0..data_size).map(|i| (i * 17) as u8).collect(), // Pseudo-random pattern
    ];
    
    // Measure timing for each data pattern multiple times
    for _ in 0..5 {
        for data in &test_data {
            let nonce = generate_secure_nonce()?;
            analyzer.measure(|| {
                encrypt_aes_gcm(&key, &nonce, data, &[])
            })?;
        }
    }
    
    analyzer.analyze_timing_security()
}

/// Test AES-GCM decryption timing for constant-time behavior
pub fn test_aes_gcm_decryption_timing() -> Result<TimingAnalysisResult, CryptoError> {
    use crate::shared::crypto::{encrypt_aes_gcm, decrypt_aes_gcm, generate_random_key, generate_secure_nonce};
    
    let mut analyzer = TimingAnalyzer::new("aes_gcm_decryption_same_size");
    let key = generate_random_key()?;
    
    // Prepare test ciphertexts of same size but different patterns
    let mut ciphertexts = Vec::new();
    let data_size = 4096;
    
    let test_patterns = [
        vec![0u8; data_size],           // All zeros
        vec![0xFFu8; data_size],        // All ones
        vec![0xAAu8; data_size],        // Alternating pattern
        (0..data_size).map(|i| i as u8).collect(), // Sequential pattern
    ];
    
    for pattern in &test_patterns {
        let nonce = generate_secure_nonce()?;
        let ciphertext = encrypt_aes_gcm(&key, &nonce, pattern, &[])?;
        ciphertexts.push((nonce, ciphertext));
    }
    
    // Measure decryption timing for same-size data with different patterns
    for _ in 0..8 {
        for (nonce, ciphertext) in &ciphertexts {
            analyzer.measure(|| {
                decrypt_aes_gcm(&key, nonce, ciphertext, &[])
            })?;
        }
    }
    
    analyzer.analyze_timing_security()
}

/// Run comprehensive timing attack tests
pub fn run_timing_security_tests() -> Result<Vec<TimingAnalysisResult>, CryptoError> {
    let mut results = Vec::new();
    
    println!("🔬 Running timing attack security tests...");
    
    // Test password validation timing
    println!("   Testing password validation timing...");
    results.push(test_password_validation_timing()?);
    
    // Test AES-GCM encryption timing
    println!("   Testing AES-GCM encryption timing...");
    results.push(test_aes_gcm_timing()?);
    
    // Test AES-GCM decryption timing
    println!("   Testing AES-GCM decryption timing...");
    results.push(test_aes_gcm_decryption_timing()?);
    
    println!("✅ Timing attack tests completed");
    
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_timing_analyzer_basic() {
        let mut analyzer = TimingAnalyzer::new("test_operation");
        
        // Add some sample timings
        analyzer.add_sample(Duration::from_nanos(1000));
        analyzer.add_sample(Duration::from_nanos(1100));
        analyzer.add_sample(Duration::from_nanos(1050));
        analyzer.add_sample(Duration::from_nanos(1080));
        analyzer.add_sample(Duration::from_nanos(1020));
        analyzer.add_sample(Duration::from_nanos(1060));
        analyzer.add_sample(Duration::from_nanos(1040));
        analyzer.add_sample(Duration::from_nanos(1070));
        analyzer.add_sample(Duration::from_nanos(1030));
        analyzer.add_sample(Duration::from_nanos(1090));
        
        let result = analyzer.analyze_timing_security().unwrap();
        assert_eq!(result.sample_count, 10);
        assert_eq!(result.operation_name, "test_operation");
    }
    
    #[test]
    fn test_timing_analyzer_measure() {
        let mut analyzer = TimingAnalyzer::new("test_measure");
        
        // Measure a simple operation
        let result = analyzer.measure(|| {
            std::thread::sleep(Duration::from_millis(1));
            42
        });
        
        assert_eq!(result, 42);
        assert_eq!(analyzer.samples.len(), 1);
        assert!(analyzer.samples[0] >= Duration::from_millis(1));
    }
    
    #[test]
    fn test_timing_vulnerability_detection() {
        let mut analyzer = TimingAnalyzer::new("vulnerable_operation");
        
        // Add samples with very high variation (potential vulnerability)
        for i in 0..20 {
            let base_time = 1000;
            let variation = if i % 2 == 0 { 0 } else { 1000 }; // Very high variation (100%)
            analyzer.add_sample(Duration::from_nanos(base_time + variation));
        }
        
        let result = analyzer.analyze_timing_security().unwrap();
        assert!(result.has_timing_vulnerabilities());
        assert!(result.vulnerabilities.iter().any(|v| v.contains("High timing variation")));
    }
    
    #[test]
    fn test_timing_range_vulnerability() {
        let mut analyzer = TimingAnalyzer::new("range_vulnerable");
        
        // Add samples with very large range differences
        analyzer.add_sample(Duration::from_nanos(1000));  // Min
        for _ in 0..8 {
            analyzer.add_sample(Duration::from_nanos(1100));
        }
        analyzer.add_sample(Duration::from_nanos(10000)); // Max (10x difference, > 5.0 threshold)
        
        let result = analyzer.analyze_timing_security().unwrap();
        assert!(result.has_timing_vulnerabilities());
        assert!(result.vulnerabilities.iter().any(|v| v.contains("Large timing range")));
    }
    
    #[test]
    fn test_good_timing_no_false_positives() {
        let mut analyzer = TimingAnalyzer::new("secure_operation");
        
        // Add samples with low, reasonable variation
        for i in 0..50 {
            let base_time = 1000;
            let small_variation = (i % 10) * 2; // Very small variation
            analyzer.add_sample(Duration::from_nanos(base_time + small_variation));
        }
        
        let result = analyzer.analyze_timing_security().unwrap();
        assert!(!result.has_timing_vulnerabilities(), 
                "False positive timing vulnerability detected: {:?}", result.vulnerabilities);
    }
}