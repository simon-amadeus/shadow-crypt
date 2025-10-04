//! # Cryptographic Algorithm Integration Tests
//!
//! These tests validate the complete algorithm abstraction layer
//! and ensure all algorithms work consistently together.

use shadow_crypt::infrastructure::crypto::{
    Algorithm, AlgorithmId, CryptographicAlgorithm, EncryptionConfig, KeyDerivationConfig,
};

#[test]
fn test_algorithm_enum_comprehensive() {
    // Test all supported algorithms through the unified enum interface
    let algorithms = vec![
        Algorithm::xchacha20_poly1305_test(),
        Algorithm::aes256_gcm_test(),
        Algorithm::from_id(AlgorithmId::XChaCha20Poly1305),
        Algorithm::test_from_id(AlgorithmId::Aes256Gcm),
        Algorithm::default(),
    ];

    for (i, algo) in algorithms.iter().enumerate() {
        println!("Testing algorithm variant {}: {:?}", i, algo.algorithm_id());
        
        // Test key derivation
        let salt = algo.generate_salt().unwrap();
        assert_eq!(salt.len(), algo.salt_length());
        
        let key = algo.derive_key_material("test_password_123", &salt).unwrap();
        assert_eq!(key.len(), algo.key_size());
        
        // Test encryption/decryption
        let plaintext = format!("Hello from algorithm {}! This is test data.", i);
        let encrypted = algo.encrypt(plaintext.as_bytes(), &key).unwrap();
        
        assert_eq!(encrypted.nonce.len(), algo.nonce_size());
        assert!(encrypted.ciphertext.len() > plaintext.len()); // Includes auth tag
        
        let decrypted = algo.decrypt(&encrypted.ciphertext, &encrypted.nonce, &key).unwrap();
        assert_eq!(plaintext.as_bytes(), decrypted);
    }
}

#[test]
fn test_cross_algorithm_interoperability() {
    // Verify different algorithms handle same data correctly
    let test_data = "The quick brown fox jumps over the lazy dog. 🦊";
    let password = "super_secure_password_2024";
    
    let xchacha = Algorithm::xchacha20_poly1305_test();
    let aes = Algorithm::aes256_gcm_test();
    
    // Each algorithm should produce different outputs for same input
    let salt1 = xchacha.generate_salt().unwrap();
    let salt2 = aes.generate_salt().unwrap();
    
    let key1 = xchacha.derive_key_material(password, &salt1).unwrap();
    let key2 = aes.derive_key_material(password, &salt2).unwrap();
    
    let encrypted1 = xchacha.encrypt(test_data.as_bytes(), &key1).unwrap();
    let encrypted2 = aes.encrypt(test_data.as_bytes(), &key2).unwrap();
    
    // Different algorithms should produce different ciphertext
    assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    assert_ne!(encrypted1.nonce.len(), encrypted2.nonce.len()); // XChaCha20: 24, AES: 12
    
    // Each should decrypt correctly with its own algorithm
    let decrypted1 = xchacha.decrypt(&encrypted1.ciphertext, &encrypted1.nonce, &key1).unwrap();
    let decrypted2 = aes.decrypt(&encrypted2.ciphertext, &encrypted2.nonce, &key2).unwrap();
    
    assert_eq!(test_data.as_bytes(), decrypted1);
    assert_eq!(test_data.as_bytes(), decrypted2);
}

#[test]
fn test_algorithm_properties_consistency() {
    // Verify algorithm properties are correctly reported
    let xchacha = Algorithm::xchacha20_poly1305_test();
    let aes = Algorithm::aes256_gcm_test();
    
    // XChaCha20-Poly1305 properties
    assert_eq!(xchacha.algorithm_id(), AlgorithmId::XChaCha20Poly1305);
    assert_eq!(xchacha.algorithm_name(), "XChaCha20-Poly1305");
    assert_eq!(xchacha.key_size(), 32); // 256-bit key
    assert_eq!(xchacha.nonce_size(), 24); // 192-bit extended nonce
    assert_eq!(xchacha.salt_length(), 16); // 128-bit salt
    assert_eq!(xchacha.name(), "Argon2id"); // Key derivation
    
    // AES-256-GCM properties
    assert_eq!(aes.algorithm_id(), AlgorithmId::Aes256Gcm);
    assert_eq!(aes.algorithm_name(), "AES-256-GCM");
    assert_eq!(aes.key_size(), 32); // 256-bit key
    assert_eq!(aes.nonce_size(), 12); // 96-bit nonce
    assert_eq!(aes.salt_length(), 16); // 128-bit salt
    assert_eq!(aes.name(), "Argon2id"); // Key derivation
}

#[test]
fn test_algorithm_security_validation() {
    // Test security properties and edge cases
    let algo = Algorithm::xchacha20_poly1305_test();
    
    // Test with empty data
    let salt = algo.generate_salt().unwrap();
    let key = algo.derive_key_material("password", &salt).unwrap();
    
    let empty_data = b"";
    let encrypted = algo.encrypt(empty_data, &key).unwrap();
    let decrypted = algo.decrypt(&encrypted.ciphertext, &encrypted.nonce, &key).unwrap();
    assert_eq!(empty_data, decrypted.as_slice());
    
    // Test with large data
    let large_data = vec![0u8; 1_000_000]; // 1MB
    let encrypted = algo.encrypt(&large_data, &key).unwrap();
    let decrypted = algo.decrypt(&encrypted.ciphertext, &encrypted.nonce, &key).unwrap();
    assert_eq!(large_data, decrypted);
    
    // Test deterministic key derivation
    let key1 = algo.derive_key_material("same_password", &salt).unwrap();
    let key2 = algo.derive_key_material("same_password", &salt).unwrap();
    assert_eq!(key1.as_bytes(), key2.as_bytes());
    
    // Test different passwords produce different keys
    let key3 = algo.derive_key_material("different_password", &salt).unwrap();
    assert_ne!(key1.as_bytes(), key3.as_bytes());
}

#[test]
fn test_nonce_uniqueness() {
    // Verify nonce generation produces unique values
    let algo = Algorithm::xchacha20_poly1305_test();
    let mut nonces = std::collections::HashSet::new();
    
    for _ in 0..1000 {
        let nonce = algo.generate_nonce().unwrap();
        assert_eq!(nonce.len(), algo.nonce_size());
        
        // Should be highly unlikely to generate duplicate nonces
        assert!(nonces.insert(nonce), "Duplicate nonce detected!");
    }
}

#[test]
fn test_algorithm_factory_methods() {
    // Test all factory methods produce working algorithms
    let test_methods = vec![
        ("default", Algorithm::default()),
        ("xchacha_prod", Algorithm::xchacha20_poly1305()),
        ("xchacha_test", Algorithm::xchacha20_poly1305_test()),
        ("aes_prod", Algorithm::aes256_gcm()),
        ("aes_test", Algorithm::aes256_gcm_test()),
        ("from_id_xchacha", Algorithm::from_id(AlgorithmId::XChaCha20Poly1305)),
        ("from_id_aes", Algorithm::from_id(AlgorithmId::Aes256Gcm)),
        ("test_from_id_xchacha", Algorithm::test_from_id(AlgorithmId::XChaCha20Poly1305)),
        ("test_from_id_aes", Algorithm::test_from_id(AlgorithmId::Aes256Gcm)),
    ];
    
    for (name, algo) in test_methods {
        println!("Testing factory method: {}", name);
        
        // Verify basic functionality
        let salt = algo.generate_salt().unwrap();
        let key = algo.derive_key_material("test", &salt).unwrap();
        let test_data = format!("Testing {}", name);
        
        let encrypted = algo.encrypt(test_data.as_bytes(), &key).unwrap();
        let decrypted = algo.decrypt(&encrypted.ciphertext, &encrypted.nonce, &key).unwrap();
        
        assert_eq!(test_data.as_bytes(), decrypted);
    }
}

#[test]
fn test_algorithm_support_validation() {
    // Test algorithm support checking
    assert!(Algorithm::is_supported(AlgorithmId::XChaCha20Poly1305));
    assert!(Algorithm::is_supported(AlgorithmId::Aes256Gcm));
    
    let supported = Algorithm::supported_algorithms();
    assert_eq!(supported.len(), 2);
    assert!(supported.contains(&AlgorithmId::XChaCha20Poly1305));
    assert!(supported.contains(&AlgorithmId::Aes256Gcm));
}