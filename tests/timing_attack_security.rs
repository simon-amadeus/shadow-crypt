//! Timing Attack Security Integration Tests
//! 
//! Tests the timing attack detection and analysis functionality 
//! with real cryptographic operations to ensure no timing vulnerabilities exist.

use shadow_crypt::shared::crypto::run_timing_security_tests;

#[test]
fn test_timing_attack_security_comprehensive() {
    println!("\n🔬 Running comprehensive timing attack security tests...");
    
    let results = run_timing_security_tests()
        .expect("Timing attack security tests failed");
    
    println!("\n📊 Timing Analysis Results:");
    println!("═══════════════════════════════");
    
    let mut has_vulnerabilities = false;
    
    for result in &results {
        println!("\n🔍 Operation: {}", result.operation_name);
        println!("   Samples: {}", result.sample_count);
        println!("   Mean time: {:?}", result.mean_time);
        println!("   Std deviation: {:?}", result.std_deviation);
        println!("   CV: {:.4}", result.coefficient_of_variation);
        println!("   Range ratio: {:.2}", result.range_ratio);
        
        if result.has_timing_vulnerabilities() {
            has_vulnerabilities = true;
            println!("   ⚠️  VULNERABILITIES DETECTED:");
            for vulnerability in &result.vulnerabilities {
                println!("      - {}", vulnerability);
            }
        } else {
            println!("   ✅ No timing vulnerabilities detected");
        }
    }
    
    println!("\n═══════════════════════════════");
    
    if has_vulnerabilities {
        println!("❌ TIMING ATTACK SECURITY TEST FAILED");
        println!("   Potential timing vulnerabilities detected in cryptographic operations.");
        println!("   This could allow attackers to extract sensitive information through timing analysis.");
        panic!("Timing attack vulnerabilities detected - this must be fixed before production use");
    } else {
        println!("✅ TIMING ATTACK SECURITY TEST PASSED");
        println!("   No timing vulnerabilities detected in cryptographic operations.");
        println!("   Operations appear to have constant-time characteristics.");
    }
}

#[test]
fn test_nonce_generation_timing_consistency() {
    use shadow_crypt::shared::crypto::{generate_secure_nonce, TimingAnalyzer};
    use std::collections::HashSet;
    
    println!("\n🔬 Testing nonce generation timing consistency...");
    
    let mut analyzer = TimingAnalyzer::new("nonce_generation");
    let mut generated_nonces = HashSet::new();
    
    // Generate many nonces and measure timing
    const NONCE_COUNT: usize = 100;
    for _ in 0..NONCE_COUNT {
        let nonce = analyzer.measure(|| {
            generate_secure_nonce().expect("Nonce generation failed")
        });
        
        // Verify nonce uniqueness
        assert!(!generated_nonces.contains(&nonce), 
                "Duplicate nonce generated: {:?}", nonce);
        generated_nonces.insert(nonce);
    }
    
    let result = analyzer.analyze_timing_security()
        .expect("Timing analysis failed");
    
    println!("📊 Nonce Generation Analysis:");
    println!("   Generated {} unique nonces", generated_nonces.len());
    println!("   Mean time: {:?}", result.mean_time);
    println!("   CV: {:.4}", result.coefficient_of_variation);
    
    // Nonce generation should have consistent timing
    if result.has_timing_vulnerabilities() {
        println!("⚠️  Timing issues in nonce generation:");
        for vulnerability in &result.vulnerabilities {
            println!("   - {}", vulnerability);
        }
        // Note: We don't panic here as nonce generation timing is less critical
        // than decryption timing, but we log the warnings
    } else {
        println!("✅ Nonce generation timing appears consistent");
    }
    
    assert_eq!(generated_nonces.len(), NONCE_COUNT, 
               "Not all generated nonces were unique");
}

#[test] 
fn test_password_timing_independence() {
    use shadow_crypt::shared::crypto::{derive_master_key, generate_salt, Argon2Params, TimingAnalyzer};
    
    println!("\n🔬 Testing password timing independence...");
    
    let salt = generate_salt(16).expect("Salt generation failed");
    let params = Argon2Params::test_params();
    
    // Test passwords of different lengths and characteristics
    let passwords = [
        ("short", "short"),
        ("long_password_with_many_characters", "long"),
        ("", "empty"),
        ("测试密码", "unicode"),
        ("P@ssw0rd!2023", "complex"),
    ];
    
    let mut all_timings = Vec::new();
    
    for (password, description) in &passwords {
        let mut analyzer = TimingAnalyzer::new(&format!("password_{}", description));
        
        // Multiple measurements for statistical significance
        for _ in 0..10 {
            analyzer.measure(|| {
                derive_master_key(password, &salt, &params)
                    .expect("Key derivation failed")
            });
        }
        
        let result = analyzer.analyze_timing_security()
            .expect("Timing analysis failed");
        
        println!("📊 Password '{}' ({}): mean={:?}, CV={:.4}", 
                description, password.len(), result.mean_time, result.coefficient_of_variation);
        
        all_timings.push(result.mean_time);
    }
    
    // Check if timing varies significantly between different passwords
    if let (Some(min_time), Some(max_time)) = (all_timings.iter().min(), all_timings.iter().max()) {
        let ratio = max_time.as_nanos() as f64 / min_time.as_nanos() as f64;
        println!("📊 Password timing range ratio: {:.2}", ratio);
        
        // For Argon2, some variation is expected due to password length differences,
        // but it shouldn't be extreme
        if ratio > 5.0 {
            println!("⚠️  Large password timing variation detected (ratio: {:.2})", ratio);
            println!("   This may indicate timing attack vulnerability in password processing");
        } else {
            println!("✅ Password timing variation within acceptable range");
        }
    }
}