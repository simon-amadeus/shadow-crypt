# Algorithm Implementation Guide

## Overview

This guide provides comprehensive instructions for implementing new cryptographic algorithms in Shadow, ensuring seamless integration with the existing architecture while maintaining security and performance standards.

## Architecture Foundation

Shadow's cryptographic architecture is built on three core traits that provide clean separation of concerns:

- **`KeyDerivationConfig`**: Password-based key derivation functions
- **`EncryptionConfig`**: Algorithm-specific parameters and metadata  
- **`CryptographicAlgorithm`**: Complete encryption/decryption operations

All algorithms must implement these three traits to integrate with Shadow's domain services and factory pattern.

## Implementation Steps

### 1. Define Algorithm Parameters

Create a configuration struct that holds algorithm-specific parameters:

```rust
use argon2::{Argon2, Params};

#[derive(Debug, Clone)]
pub struct YourAlgorithmParams {
    /// Key derivation parameters
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    /// Algorithm-specific parameters
    pub key_size: usize,
    pub nonce_size: usize,
}

impl YourAlgorithmParams {
    /// Production parameters (secure, slower)
    pub fn production() -> Self {
        Self {
            memory_cost: 65536,   // 64 MiB
            time_cost: 3,         // 3 iterations
            parallelism: 4,       // 4 threads
            key_size: 32,         // 256-bit keys
            nonce_size: 16,       // Algorithm-specific
        }
    }

    /// Test parameters (fast, lower security)
    pub fn test() -> Self {
        Self {
            memory_cost: 64,      // 64 KiB
            time_cost: 1,         // 1 iteration
            parallelism: 1,       // 1 thread
            key_size: 32,         // Same key size
            nonce_size: 16,       // Same nonce size
        }
    }
}

#[derive(Debug, Clone)]
pub struct YourAlgorithmConfig {
    params: YourAlgorithmParams,
}

impl YourAlgorithmConfig {
    pub fn new(params: YourAlgorithmParams) -> Self {
        Self { params }
    }
}
```

### 2. Implement KeyDerivationConfig

Provide secure password-based key derivation:

```rust
use shadow_crypt::domain::entities::KeyMaterial;
use shadow_crypt::domain::errors::DomainError;
use shadow_crypt::domain::services::KeyDerivationConfig;

impl KeyDerivationConfig for YourAlgorithmConfig {
    fn derive_key_material(&self, password: &str, salt: &[u8]) -> Result<KeyMaterial, DomainError> {
        // Use Argon2id for key derivation (recommended)
        let argon2_params = Params::new(
            self.params.memory_cost,
            self.params.time_cost,
            self.params.parallelism,
            Some(32), // Master key size
        ).map_err(|e| DomainError::crypto_error(format!("Invalid Argon2 parameters: {}", e)))?;

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2_params,
        );

        let mut master_key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut master_key)
            .map_err(|e| DomainError::crypto_error(format!("Key derivation failed: {}", e)))?;

        Ok(KeyMaterial::from_master_key(master_key))
    }

    fn salt_length(&self) -> usize {
        16 // Minimum 128-bit salt
    }

    fn name(&self) -> &'static str {
        "YourAlgorithm-Argon2id"
    }
}
```

### 3. Implement EncryptionConfig

Define algorithm parameters and metadata:

```rust
use shadow_crypt::domain::entities::AlgorithmId;
use shadow_crypt::domain::services::EncryptionConfig;

impl EncryptionConfig for YourAlgorithmConfig {
    fn key_size(&self) -> usize {
        self.params.key_size
    }

    fn nonce_size(&self) -> usize {
        self.params.nonce_size
    }

    fn algorithm_id(&self) -> AlgorithmId {
        // Add new variant to AlgorithmId enum
        AlgorithmId::YourAlgorithm // This requires updating the enum
    }
}
```

### 4. Implement CryptographicAlgorithm

Provide complete encryption/decryption operations:

```rust
use shadow_crypt::domain::services::{CryptographicAlgorithm, EncryptionResult};

impl CryptographicAlgorithm for YourAlgorithmConfig {
    fn encrypt(
        &self,
        plaintext: &[u8],
        key_material: &KeyMaterial,
    ) -> Result<EncryptionResult, DomainError> {
        // Generate cryptographically secure nonce
        let mut nonce = vec![0u8; self.nonce_size()];
        getrandom::fill(&mut nonce)
            .map_err(|_| DomainError::crypto_error("Random generation failed".to_string()))?;

        // Create cipher instance using encryption key
        let encryption_key = key_material.as_bytes();
        
        // TODO: Replace with your algorithm's encryption
        // Example using hypothetical cipher:
        // let cipher = YourCipher::new_from_slice(encryption_key)
        //     .map_err(|e| DomainError::crypto_error(format!("Cipher creation failed: {}", e)))?;
        
        // let ciphertext = cipher.encrypt(&nonce, plaintext)
        //     .map_err(|e| DomainError::crypto_error(format!("Encryption failed: {}", e)))?;

        // Placeholder implementation - NEVER use in production
        let ciphertext = plaintext.to_vec();

        Ok(EncryptionResult { ciphertext, nonce })
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        key_material: &KeyMaterial,
    ) -> Result<Vec<u8>, DomainError> {
        // Validate nonce size
        if nonce.len() != self.nonce_size() {
            return Err(DomainError::crypto_error(format!(
                "Expected nonce size {}, got {}",
                self.nonce_size(),
                nonce.len()
            )));
        }

        // Create cipher instance using encryption key
        let encryption_key = key_material.as_bytes();
        
        // TODO: Replace with your algorithm's decryption
        // Example using hypothetical cipher:
        // let cipher = YourCipher::new_from_slice(encryption_key)
        //     .map_err(|e| DomainError::crypto_error(format!("Cipher creation failed: {}", e)))?;
        
        // let plaintext = cipher.decrypt(nonce, ciphertext)
        //     .map_err(|_| DomainError::authentication_failed())?;

        // Placeholder implementation - NEVER use in production
        let plaintext = ciphertext.to_vec();

        Ok(plaintext)
    }

    fn test_config() -> Self {
        Self::new(YourAlgorithmParams::test())
    }

    fn production_config() -> Self {
        Self::new(YourAlgorithmParams::production())
    }
}
```

### 5. Update Algorithm Registry

Add your algorithm to the registry in two places:

#### A. Update AlgorithmId enum:

```rust
// In src/domain/entities/algorithm_id.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AlgorithmId {
    XChaCha20Poly1305 = 1,
    AesGcm256 = 2,
    YourAlgorithm = 3,  // Add your algorithm
}

impl AlgorithmId {
    pub fn from_u16(id: u16) -> Result<Self, DomainError> {
        match id {
            1 => Ok(AlgorithmId::XChaCha20Poly1305),
            2 => Ok(AlgorithmId::AesGcm256),
            3 => Ok(AlgorithmId::YourAlgorithm),  // Add mapping
            _ => Err(DomainError::unsupported_algorithm(id)),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            AlgorithmId::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            AlgorithmId::AesGcm256 => "AES-256-GCM",
            AlgorithmId::YourAlgorithm => "Your-Algorithm",  // Add name
        }
    }

    pub fn key_size(self) -> usize {
        match self {
            AlgorithmId::XChaCha20Poly1305 => 32,
            AlgorithmId::AesGcm256 => 32,
            AlgorithmId::YourAlgorithm => 32,  // Add key size
        }
    }

    pub fn nonce_size(self) -> usize {
        match self {
            AlgorithmId::XChaCha20Poly1305 => 24,
            AlgorithmId::AesGcm256 => 12,
            AlgorithmId::YourAlgorithm => 16,  // Add nonce size
        }
    }
}
```

#### B. Update Factory enum:

```rust
// In src/infrastructure/crypto/factory.rs
use your_module::YourAlgorithmConfig;

#[derive(Debug, Clone)]
pub enum Algorithm {
    XChaCha20Poly1305(XChaCha20Poly1305Config),
    Aes256Gcm(Aes256GcmConfig),
    YourAlgorithm(YourAlgorithmConfig),  // Add variant
}

impl Algorithm {
    pub fn from_id(id: AlgorithmId) -> Self {
        match id {
            AlgorithmId::XChaCha20Poly1305 => {
                Self::XChaCha20Poly1305(XChaCha20Poly1305Config::production_config())
            }
            AlgorithmId::AesGcm256 => {
                Self::Aes256Gcm(Aes256GcmConfig::production_config())
            }
            AlgorithmId::YourAlgorithm => {  // Add factory method
                Self::YourAlgorithm(YourAlgorithmConfig::production_config())
            }
        }
    }

    pub fn test_from_id(id: AlgorithmId) -> Self {
        match id {
            AlgorithmId::XChaCha20Poly1305 => {
                Self::XChaCha20Poly1305(XChaCha20Poly1305Config::test_config())
            }
            AlgorithmId::AesGcm256 => {
                Self::Aes256Gcm(Aes256GcmConfig::test_config())
            }
            AlgorithmId::YourAlgorithm => {  // Add test factory method
                Self::YourAlgorithm(YourAlgorithmConfig::test_config())
            }
        }
    }

    pub fn supported_algorithms() -> Vec<AlgorithmId> {
        vec![
            AlgorithmId::XChaCha20Poly1305,
            AlgorithmId::AesGcm256,
            AlgorithmId::YourAlgorithm,  // Add to supported list
        ]
    }
}

// Update trait implementations to handle new variant
impl CryptographicAlgorithm for Algorithm {
    fn encrypt(&self, plaintext: &[u8], key_material: &KeyMaterial) -> Result<EncryptionResult, DomainError> {
        match self {
            Algorithm::XChaCha20Poly1305(config) => config.encrypt(plaintext, key_material),
            Algorithm::Aes256Gcm(config) => config.encrypt(plaintext, key_material),
            Algorithm::YourAlgorithm(config) => config.encrypt(plaintext, key_material),  // Add dispatch
        }
    }

    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8], key_material: &KeyMaterial) -> Result<Vec<u8>, DomainError> {
        match self {
            Algorithm::XChaCha20Poly1305(config) => config.decrypt(ciphertext, nonce, key_material),
            Algorithm::Aes256Gcm(config) => config.decrypt(ciphertext, nonce, key_material),
            Algorithm::YourAlgorithm(config) => config.decrypt(ciphertext, nonce, key_material),  // Add dispatch
        }
    }

    // Update other trait methods similarly...
}
```

### 6. Add Comprehensive Tests

Create thorough tests for your algorithm:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_properties() {
        let config = YourAlgorithmConfig::test_config();
        assert_eq!(config.key_size(), 32);
        assert_eq!(config.nonce_size(), 16);
        assert_eq!(config.salt_length(), 16);
        assert_eq!(config.algorithm_id(), AlgorithmId::YourAlgorithm);
        assert_eq!(config.name(), "YourAlgorithm-Argon2id");
    }

    #[test]
    fn test_key_derivation() {
        let config = YourAlgorithmConfig::test_config();
        let salt = vec![0x42u8; config.salt_length()];
        
        let key_material1 = config.derive_key_material("password", &salt).unwrap();
        let key_material2 = config.derive_key_material("password", &salt).unwrap();
        
        // Same password + salt should produce same keys
        assert_eq!(key_material1, key_material2);
        
        // Different password should produce different keys
        let different_keys = config.derive_key_material("different", &salt).unwrap();
        assert_ne!(key_material1, different_keys);
    }

    #[test]
    fn test_encryption_roundtrip() {
        let config = YourAlgorithmConfig::test_config();
        let salt = vec![0x42u8; config.salt_length()];
        let key_material = config.derive_key_material("test_password", &salt).unwrap();
        
        let plaintext = b"Hello, cryptographic world!";
        let encrypted = config.encrypt(plaintext, &key_material).unwrap();
        let decrypted = config.decrypt(&encrypted.ciphertext, &encrypted.nonce, &key_material).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
        assert_eq!(encrypted.nonce.len(), config.nonce_size());
    }

    #[test]
    fn test_nonce_uniqueness() {
        let config = YourAlgorithmConfig::test_config();
        let salt = vec![0x42u8; config.salt_length()];
        let key_material = config.derive_key_material("test_password", &salt).unwrap();
        
        let plaintext = b"Same plaintext";
        let encrypted1 = config.encrypt(plaintext, &key_material).unwrap();
        let encrypted2 = config.encrypt(plaintext, &key_material).unwrap();
        
        // Nonces should be different (preventing deterministic encryption)
        assert_ne!(encrypted1.nonce, encrypted2.nonce);
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }

    #[test]
    fn test_invalid_nonce_size() {
        let config = YourAlgorithmConfig::test_config();
        let salt = vec![0x42u8; config.salt_length()];
        let key_material = config.derive_key_material("test_password", &salt).unwrap();
        
        let ciphertext = vec![0u8; 32];
        let wrong_nonce = vec![0u8; config.nonce_size() + 1]; // Wrong size
        
        let result = config.decrypt(&ciphertext, &wrong_nonce, &key_material);
        assert!(result.is_err());
    }
}
```

### 7. Integration with Factory Pattern

The factory pattern automatically supports your algorithm once you've updated the `Algorithm` enum. Test integration:

```rust
#[test]
fn test_factory_integration() {
    use shadow_crypt::infrastructure::crypto::factory::Algorithm;
    
    let algorithm = Algorithm::from_id(AlgorithmId::YourAlgorithm);
    assert_eq!(algorithm.algorithm_id(), AlgorithmId::YourAlgorithm);
    
    let test_algorithm = Algorithm::test_from_id(AlgorithmId::YourAlgorithm);
    assert_eq!(test_algorithm.algorithm_id(), AlgorithmId::YourAlgorithm);
    
    assert!(Algorithm::is_supported(AlgorithmId::YourAlgorithm));
}
```

## Security Requirements

### Mandatory Security Features

1. **Authenticated Encryption**: Use AEAD (Authenticated Encryption with Associated Data)
2. **Secure Random Nonces**: Use `getrandom` for cryptographically secure nonce generation
3. **Constant-Time Operations**: Avoid timing side-channels in critical operations
4. **Key Zeroization**: KeyMaterial automatically handles secure memory cleanup
5. **Input Validation**: Validate all parameters and fail fast on invalid inputs

### Post-Quantum Considerations

For post-quantum algorithms:

1. **Larger Key Sizes**: Update `key_size()` method to return appropriate size
2. **Extended Nonces**: Use larger nonces for quantum-resistant security margins
3. **Hybrid Approaches**: Combine classical and post-quantum algorithms
4. **Algorithm-Specific Metadata**: Use TLV headers for additional parameters

### Performance Guidelines

1. **Production vs Test Configs**: Provide both secure (slow) and fast (testing) parameter sets
2. **Memory Management**: Minimize allocations in hot paths
3. **Batch Operations**: Support batch encryption for large datasets
4. **Hardware Acceleration**: Leverage platform-specific optimizations when available

## TLV Header Integration

If your algorithm requires additional metadata in file headers:

```rust
// Add new TLV field types in src/domain/entities/tlv_header.rs
pub enum TlvFieldType {
    // ... existing fields ...
    YourAlgorithmParams = 0x20,  // Use available field type space
}

// Update from_u8 implementation
impl From<u8> for TlvFieldType {
    fn from(value: u8) -> Self {
        match value {
            // ... existing mappings ...
            0x20 => TlvFieldType::YourAlgorithmParams,
            _ => TlvFieldType::ExtensionMarker,
        }
    }
}
```

## Testing Strategy

### Unit Tests
- Algorithm parameter validation
- Key derivation correctness  
- Encryption/decryption roundtrips
- Nonce uniqueness
- Error handling

### Integration Tests
- Factory pattern integration
- Cross-algorithm compatibility  
- TLV header serialization
- Performance benchmarks

### Security Tests
- Side-channel resistance
- Known answer tests (KATs)
- Fuzzing with invalid inputs
- Memory safety validation

## Module Organization

Place your algorithm implementation in:

```
src/infrastructure/crypto/
├── your_algorithm.rs      # Algorithm implementation
├── factory.rs            # Update factory enum
└── mod.rs               # Update module exports
```

Update module exports:

```rust
// In src/infrastructure/crypto/mod.rs
pub mod your_algorithm;
pub use your_algorithm::YourAlgorithmConfig;
```

## Performance Benchmarks

Add benchmarks to validate performance:

```rust
// In tests/efficiency_benchmarks.rs
#[cfg(test)]
mod your_algorithm_benchmarks {
    use super::*;
    use std::time::Instant;

    #[test]
    fn benchmark_your_algorithm_encryption() {
        let config = YourAlgorithmConfig::test_config();
        let key_material = setup_test_key_material(&config);
        let data = vec![0u8; 1024 * 1024]; // 1MB test data
        
        let start = Instant::now();
        let _encrypted = config.encrypt(&data, &key_material).unwrap();
        let duration = start.elapsed();
        
        println!("YourAlgorithm 1MB encryption: {:?}", duration);
    }
}
```

## Documentation Requirements

1. **Algorithm Security Analysis**: Document security properties and limitations
2. **Performance Characteristics**: Benchmark results and optimization notes
3. **Parameter Rationale**: Justify parameter choices for production/test configs
4. **Migration Path**: How existing files remain compatible
5. **Usage Examples**: Clear examples for algorithm integrators

## Validation Checklist

Before submitting your algorithm implementation:

- [ ] All three traits implemented correctly
- [ ] AlgorithmId enum updated with new variant
- [ ] Factory pattern updated with dispatch logic
- [ ] Comprehensive test suite with >95% coverage
- [ ] Security review completed
- [ ] Performance benchmarks meet requirements
- [ ] Documentation written and reviewed
- [ ] TLV compatibility verified if metadata needed
- [ ] Cross-algorithm tests pass
- [ ] Memory safety validated

## Future Evolution

The architecture supports algorithm evolution through:

1. **Versioned Algorithm IDs**: Add new IDs for algorithm variants
2. **Parameter Evolution**: Use TLV headers for extended parameters
3. **Hybrid Algorithms**: Combine multiple algorithms in single implementation
4. **Hardware Acceleration**: Platform-specific optimizations via trait specialization

This guide ensures new algorithms integrate seamlessly while maintaining Shadow's security, performance, and architectural standards.