# Preserved Architecture Patterns for Shadow Rewrite

This document specifies the architectural patterns from the current implementation that should be preserved in the rewrite due to their excellent design.

## 🏗️ **Core Architectural Patterns**

### 1. **TLV Header System (New V1 Format)**
**Status**: 🎯 **PRESERVE EXACTLY**

The current V3 TLV (Type-Length-Value) header system is exceptionally well-designed and should be preserved as the new V1 format for the rewrite:

**Important**: This was previously called "V3" in the legacy codebase, but will become the canonical "V1" format in the rewrite. Legacy V1 and V2 formats should be completely removed.

```rust
/// TLV field structure: [Type(1)][Length(4)][Value(Length)]
#[derive(Debug, Clone)]
pub struct TlvField {
    pub field_type: TlvFieldType,
    pub data: Vec<u8>,
}

/// Extensible field types
#[repr(u8)]
pub enum TlvFieldType {
    OriginalFilename = 0x01,
    DirectoryPath = 0x02, 
    FileMetadata = 0x03,
    CompressionSettings = 0x04,
    KeyDerivationParams = 0x05,
    CustomAttributes = 0x06,
    ContentHash = 0x07,
    CreatedBy = 0x08,
    ExtensionMarker = 0xFF,  // For unknown future fields
}
```

**Design Strengths:**
- **Future-Proof**: New fields can be added without breaking compatibility
- **Algorithm-Agnostic**: Variable nonce lengths support any cryptographic algorithm
- **Deterministic**: Consistent serialization order ensures reproducible headers
- **Graceful Degradation**: Unknown fields preserved during roundtrip operations
- **Space Efficient**: Only stores what's actually needed

**Header Structure:**
```
[MAGIC(6)][VERSION(2)][ALGORITHM_ID(2)][HEADER_LENGTH(4)]
[NONCE_LENGTH(1)][NONCE(var)][SALT(32)][TLV_FIELDS(var)][AUTH_TAG(16)]
```

### 2. **Configuration Provider Pattern**
**Status**: 🎯 **PRESERVE WITH ENHANCEMENTS**

The trait-based configuration system provides excellent dependency injection:

```rust
/// Core configuration traits
pub trait KeyDerivationConfig: Send + Sync + Clone {
    fn derive_key_material(&self, password: &str, salt: &[u8]) -> Result<KeyMaterial, CryptoError>;
    fn salt_length(&self) -> usize;
    fn generate_salt(&self) -> Result<Vec<u8>, CryptoError>;
    fn name(&self) -> &'static str;
}

pub trait EncryptionConfig: Send + Sync + Clone {
    fn key_size(&self) -> usize;
    fn nonce_size(&self) -> usize;
    fn algorithm_id(&self) -> u16;
    fn algorithm_name(&self) -> &'static str;
}

pub trait CryptoConfig: KeyDerivationConfig + EncryptionConfig {
    fn test_config() -> Self;      // Fast parameters for testing
    fn production_config() -> Self; // Secure parameters for production
}

/// Dependency injection interface
pub trait ConfigProvider {
    type Config: CryptoConfig;
    fn config(&self) -> &Self::Config;
}
```

**Design Strengths:**
- **Clean Dependency Injection**: Functions accept providers, not concrete types
- **Test/Production Separation**: Built-in configuration variants
- **Algorithm Decoupling**: Business logic independent of crypto implementations
- **Composable Design**: Separate concerns that can be combined

### 3. **Version Compatibility Matrix**
**Status**: 🎯 **PRESERVE AND EXTEND**

The version compatibility system provides robust migration planning:

```rust
pub struct CompatibilityMatrix;

impl CompatibilityMatrix {
    /// Check if source version can migrate to target version
    pub fn can_migrate(source_version: u16, target_version: u16) -> bool;
    
    /// Get supported migration paths from a version  
    pub fn migration_paths(source_version: u16) -> Vec<u16>;
    
    /// Check version capabilities
    pub fn can_read(version: u16) -> bool;
    pub fn can_write(version: u16) -> bool;
}

pub trait VersionedHeader: Sized {
    const VERSION: u16;
    fn serialize(&self) -> Vec<u8>;
    fn deserialize(data: &[u8]) -> Result<(Self, usize), CryptoError>;
    fn validate(&self) -> Result<(), CryptoError>;
    fn magic() -> &'static [u8];
    fn can_migrate_to(target_version: u16) -> bool;
    fn can_migrate_from(source_version: u16) -> bool;
}
```

**Design Strengths:**
- **Migration Planning**: Clear upgrade paths between versions
- **Capability Matrix**: Know what each version supports
- **Extensible**: Easy to add new versions
- **Safety**: Explicit compatibility prevents data corruption

### 4. **Error Handling Philosophy**
**Status**: 🎯 **PRESERVE APPROACH, REFINE IMPLEMENTATION**

The current error handling strikes the right balance between helpfulness and security:

```rust
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("File system error: {0}")]
    FileSystemError(#[from] std::io::Error),
    
    #[error("Header parsing error: {0}")]
    HeaderParsingError(String),
    
    // ... other variants
}

impl CryptoError {
    /// Get user-friendly error message with actionable suggestions
    pub fn user_friendly_message(&self) -> String {
        match self {
            CryptoError::AuthenticationFailed => {
                "Decryption failed - this usually means an incorrect password.\n\n\
                Suggestions:\n\
                • Double-check your password (case-sensitive)\n\
                • Verify the file wasn't corrupted during transfer\n\
                • Make sure this is a valid encrypted file".to_string()
            }
            // ... other helpful messages
        }
    }
}
```

**Design Principles:**
- **User-Friendly**: Non-technical explanations with actionable hints
- **Security-Conscious**: No sensitive implementation details leaked
- **Context Preservation**: Maintains error chain for debugging
- **Actionable Guidance**: Tells users what to do, not just what failed

## 🔧 **Supporting Infrastructure**

### 5. **Secure Memory Management**
**Status**: 🎯 **PRESERVE AND ENHANCE**

The current secure memory system provides proper cryptographic hygiene:

```rust
pub struct KeyMaterial {
    data: SecureBox<[u8]>,
}

impl KeyMaterial {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data: SecureBox::new(data.into_boxed_slice()),
        }
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        // Automatic zeroization via SecureBox
    }
}
```

### 6. **File Detection Logic**
**Status**: 🎯 **PRESERVE CORE, ENHANCE FEATURES**

The double-encryption prevention is robust and should be preserved:

```rust
pub fn is_encrypted_file(path: &Path) -> Result<bool, CryptoError> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 6];
    
    if file.read_exact(&mut magic).is_err() {
        return Ok(false); // File too short
    }
    
    Ok(magic == *b"SHADOW")
}
```

### 7. **Progress Reporting System**
**Status**: 🎯 **PRESERVE CONCEPT, STANDARDIZE INTERFACE**

The progress reporting provides good user feedback:

```rust
pub struct ProgressReporter {
    start_time: Instant,
    show_progress: bool,
}

impl ProgressReporter {
    pub fn new(show_progress: bool) -> Self;
    pub fn report_progress(&self, message: &str);
    pub fn report_completion(&self, message: &str, duration: Duration);
}
```

## 📋 **Rewrite Implementation Strategy**

### Phase 1: Core Infrastructure
1. **Implement TLV Header System** - Preserve current V3 design as new V1 format
2. **Build Configuration Provider Pattern** - Trait-based dependency injection
3. **Create Version Compatibility Matrix** - Future-proof migration system (V1 as baseline)
4. **Establish Error Handling** - User-friendly, security-conscious errors

### Phase 2: Cryptographic Layer
1. **Secure Memory Management** - Key material protection
2. **Algorithm Abstraction** - Pluggable crypto implementations
3. **File Detection** - Double-encryption prevention
4. **Content Hashing** - Integrity verification infrastructure

### Phase 3: Domain Logic
1. **File Processing Pipeline** - Encryption/decryption workflows
2. **Batch Operations** - Multi-file processing
3. **Migration Services** - Future version upgrade capabilities (from V1 base)
4. **CLI Integration** - User interface layer

### Design Principles for Rewrite
1. **Preserve Excellent Patterns**: Don't fix what isn't broken
2. **Complete Missing Features**: Implement documented but missing functionality
3. **Clean Version Slate**: V1 as the only supported format initially
4. **Enhance User Experience**: Better CLI consistency and error messages
5. **Security First**: No compromises on cryptographic security