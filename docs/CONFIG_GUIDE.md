# Configuration System Developer Guide

This guide provides practical examples and patterns for using Shadow's trait-based configuration system.

## Quick Start

### Basic Usage with Default Configurations

```rust
use shadow_crypt::shared::algorithms::{
    AesGcmConfig, XChaCha20Config, DefaultConfigProvider,
    encrypt_with_provider, decrypt_with_provider
};

// Create a test configuration provider
let provider = DefaultConfigProvider::<AesGcmConfig>::test();

// Encrypt a file
encrypt_with_provider(&input_path, &output_path, "password", false, &provider)?;

// Decrypt a file  
decrypt_with_provider(&encrypted_path, &restored_path, "password", &provider)?;
```

### Custom Configuration Parameters

```rust
// Create custom configuration for specific security requirements
let custom_config = AesGcmConfig::with_params(
    2048,  // Custom memory cost (higher = more secure, slower)
    2,     // Custom time cost 
    2      // Custom parallelism
);
let provider = DefaultConfigProvider::new(custom_config);

// Use the custom configuration
encrypt_with_provider(&input_path, &output_path, "password", false, &provider)?;
```

## Algorithm-Agnostic Development

### Writing Generic Functions

```rust
use shadow_crypt::shared::algorithms::{CryptoConfig, ConfigProvider};

// Function that works with any algorithm
fn backup_file<P: ConfigProvider>(
    source: &Path, 
    backup_dir: &Path,
    password: &str,
    provider: &P
) -> Result<(), CryptoError> {
    let backup_path = backup_dir.join(format!("{}.shadow", 
        source.file_name().unwrap().to_string_lossy()));
    
    encrypt_with_provider(source, &backup_path, password, false, provider)
}

// Works with any algorithm configuration
let aes_provider = DefaultConfigProvider::<AesGcmConfig>::production();
let xchacha20_provider = DefaultConfigProvider::<XChaCha20Config>::production();

backup_file(&my_file, &backup_dir, "password", &aes_provider)?;
backup_file(&my_file, &backup_dir, "password", &xchacha20_provider)?;
```

### Configuration Comparison

```rust
fn compare_algorithm_performance<C1, C2>(config1: &C1, config2: &C2) 
where 
    C1: CryptoConfig,
    C2: CryptoConfig,
{
    println!("Algorithm 1: {} (ID: {})", 
        config1.algorithm_name(), config1.algorithm_id());
    println!("  Key size: {} bytes", config1.key_size());
    println!("  Nonce size: {} bytes", config1.nonce_size());
    
    println!("Algorithm 2: {} (ID: {})", 
        config2.algorithm_name(), config2.algorithm_id());
    println!("  Key size: {} bytes", config2.key_size());
    println!("  Nonce size: {} bytes", config2.nonce_size());
}
```

## Testing Patterns

### Basic Test Setup

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs::write;
    
    #[test]
    fn test_encryption_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let original = temp_dir.path().join("test.txt");
        let encrypted = temp_dir.path().join("test.shadow");
        let decrypted = temp_dir.path().join("test_restored.txt");
        
        // Create test content
        write(&original, "Hello, configuration world!").unwrap();
        
        // Use test configuration (fast parameters)
        let provider = DefaultConfigProvider::<AesGcmConfig>::test();
        
        // Test encryption/decryption
        encrypt_with_provider(&original, &encrypted, "password", false, &provider).unwrap();
        decrypt_with_provider(&encrypted, &decrypted, "password", &provider).unwrap();
        
        // Verify content
        let original_content = std::fs::read_to_string(&original).unwrap();
        let decrypted_content = std::fs::read_to_string(&decrypted).unwrap();
        assert_eq!(original_content, decrypted_content);
    }
}
```

### Algorithm-Agnostic Testing

```rust
// Test that works with any algorithm
fn test_algorithm_roundtrip<C: CryptoConfig>(config: C) {
    let temp_dir = TempDir::new().unwrap();
    let original = temp_dir.path().join("test.txt");
    let encrypted = temp_dir.path().join("test.shadow");
    let decrypted = temp_dir.path().join("test_restored.txt");
    
    write(&original, "Algorithm-agnostic test content").unwrap();
    
    let provider = DefaultConfigProvider::new(config);
    
    encrypt_with_provider(&original, &encrypted, "password", false, &provider).unwrap();
    decrypt_with_provider(&encrypted, &decrypted, "password", &provider).unwrap();
    
    let original_content = std::fs::read_to_string(&original).unwrap();
    let decrypted_content = std::fs::read_to_string(&decrypted).unwrap();
    assert_eq!(original_content, decrypted_content);
}

#[test]
fn test_all_algorithms() {
    // Test with AES-GCM
    test_algorithm_roundtrip(AesGcmConfig::test_config());
    
    // Test with XChaCha20
    test_algorithm_roundtrip(XChaCha20Config::test_config());
}
```

### Mock Configurations for Edge Cases

```rust
#[derive(Clone)]
struct MockFailingConfig;

impl KeyDerivationConfig for MockFailingConfig {
    fn derive_key_material(&self, _password: &str, _salt: &[u8]) -> Result<KeyMaterial, CryptoError> {
        Err(CryptoError::CryptographicError("Simulated key derivation failure".to_string()))
    }
    
    fn name(&self) -> &'static str { "FailingMock" }
}

impl EncryptionConfig for MockFailingConfig {
    fn key_size(&self) -> usize { 32 }
    fn nonce_size(&self) -> usize { 12 }
    fn algorithm_id(&self) -> u16 { 999 }
    fn algorithm_name(&self) -> &'static str { "MockFailure" }
}

impl CryptoConfig for MockFailingConfig {
    fn test_config() -> Self { Self }
    fn production_config() -> Self { Self }
}

#[test]
fn test_key_derivation_failure() {
    let provider = DefaultConfigProvider::new(MockFailingConfig);
    let result = encrypt_with_provider(&input, &output, "password", false, &provider);
    assert!(result.is_err());
}
```

## Migration Guide

### Step 1: Identify Legacy Patterns

Look for these patterns in your code:
```rust
// OLD: Manual parameter injection
let params = Argon2Params::test_params();
encrypt_single_file_with_params(&input, &output, password, false, &params)?;

// OLD: Direct parameter construction
let params = Argon2Params::custom(1024, 1, 1);
```

### Step 2: Replace with Configuration Providers

```rust
// NEW: Use configuration providers
let provider = DefaultConfigProvider::<AesGcmConfig>::test();
encrypt_with_provider(&input, &output, password, false, &provider)?;

// NEW: Custom configuration
let custom_config = AesGcmConfig::with_params(1024, 1, 1);
let provider = DefaultConfigProvider::new(custom_config);
```

### Step 3: Leverage Generic Operations

```rust
// OLD: Algorithm-specific functions
encrypt_single_file_with_params(&input, &output, password, false, &params)?;

// NEW: Generic operations
encrypt_with_provider(&input, &output, password, false, &provider)?;
// or
encrypt_with_config(&input, &output, password, false, provider.config())?;
```

### Step 4: Update Test Functions

```rust
// OLD: Tests coupled to specific parameter types
#[test]
fn test_encryption() {
    let params = Argon2Params::test_params();
    // ... test code using params
}

// NEW: Tests using configuration providers
#[test]
fn test_encryption() {
    let provider = DefaultConfigProvider::<AesGcmConfig>::test();
    // ... test code using provider
}
```

## Best Practices

### Configuration Selection

**Test Configurations**: Use `::test()` for unit tests (fast parameters)
```rust
let provider = DefaultConfigProvider::<AesGcmConfig>::test();
```

**Production Configurations**: Use `::production()` for real usage (secure parameters)
```rust
let provider = DefaultConfigProvider::<AesGcmConfig>::production();
```

**Custom Configurations**: Use `::with_params()` for specific requirements
```rust
let config = AesGcmConfig::with_params(memory_cost, time_cost, parallelism);
```

### Algorithm Independence

**Write Generic Functions**: Accept `ConfigProvider` or `CryptoConfig` traits
```rust
fn secure_backup<P: ConfigProvider>(provider: &P) -> Result<(), CryptoError> {
    // Works with any algorithm
}
```

**Avoid Algorithm-Specific Types**: Use traits instead of concrete types
```rust
// Good: Generic
fn process_config<C: CryptoConfig>(config: &C) { }

// Avoid: Algorithm-specific
fn process_config(config: &AesGcmConfig) { }
```

### Testing Strategy

**Use Fast Test Configurations**: Always use `::test()` configurations in tests
**Test Multiple Algorithms**: Use generic test functions when possible
**Mock Edge Cases**: Create mock configurations to test error conditions
**Validate Configuration Properties**: Test that configurations have expected properties

## Advanced Patterns

### Configuration Factories

```rust
pub struct ConfigurationFactory;

impl ConfigurationFactory {
    pub fn for_security_level(level: SecurityLevel) -> impl ConfigProvider {
        match level {
            SecurityLevel::Fast => DefaultConfigProvider::<AesGcmConfig>::test(),
            SecurityLevel::Balanced => DefaultConfigProvider::<AesGcmConfig>::production(),
            SecurityLevel::Maximum => {
                let config = AesGcmConfig::with_params(131072, 5, 8); // High security
                DefaultConfigProvider::new(config)
            }
        }
    }
}
```

### Runtime Algorithm Selection

```rust
pub enum AlgorithmChoice {
    AesGcm,
    XChaCha20,
}

pub fn create_provider(choice: AlgorithmChoice) -> Box<dyn ConfigProvider<Config = dyn CryptoConfig>> {
    match choice {
        AlgorithmChoice::AesGcm => Box::new(DefaultConfigProvider::<AesGcmConfig>::production()),
        AlgorithmChoice::XChaCha20 => Box::new(DefaultConfigProvider::<XChaCha20Config>::production()),
    }
}
```

This pattern requires trait objects and is more complex but enables runtime algorithm selection.

## Troubleshooting

### Common Issues

**Configuration Type Mismatch**: Make sure your provider's config type matches your algorithm
```rust
// Wrong: XChaCha20 provider with AES config
let provider = DefaultConfigProvider::<XChaCha20Config>::test();
let aes_params = provider.config().argon2_params(); // Error!

// Right: Matching types
let provider = DefaultConfigProvider::<AesGcmConfig>::test();
let aes_params = provider.config().argon2_params(); // OK
```

**Missing Trait Bounds**: Functions need proper trait bounds
```rust
// Wrong: Missing bounds
fn test_config<T>(config: T) { }

// Right: Proper bounds
fn test_config<T: CryptoConfig>(config: T) { }
```

**Legacy Function Usage**: Use new generic operations
```rust
// Old: Algorithm-specific
encrypt_single_file_with_params(&input, &output, password, false, &params)?;

// New: Generic
encrypt_with_provider(&input, &output, password, false, &provider)?;
```

## Future Extensibility

The configuration system is designed for easy extension:

### Adding New Algorithms

1. **Create Configuration Struct**: Implement `CryptoConfig` traits
2. **Implement Core Operations**: Add to `generic_ops.rs` dispatch 
3. **Add Tests**: Use existing configuration provider patterns
4. **Update Documentation**: Follow established patterns

### Adding Configuration Options

1. **Extend Trait Methods**: Add new methods to configuration traits
2. **Update Implementations**: Implement new methods in concrete configs
3. **Maintain Backward Compatibility**: Use default implementations when possible

The trait-based system ensures that new algorithms integrate seamlessly with existing code.