# File Encryption Program: Comprehensive Design Specification

## Executive Summary

This document presents a comprehensive design for a high-security, high-performance file encryption program written in Rust. The system supports single file and directory encryption with reversible filename obfuscation, advanced features like partial decryption, and maintains extreme security through proven cryptographic primitives and careful implementation practices.

## 1. Core Requirements & Architecture

### 1.1 Fundamental Requirements
- **Encryption**: Single files and directories (recursive) using AES-256-CBC + HMAC-SHA256
- **Filename Obfuscation**: Reversible, no manifest required
- **Security**: Extreme security with per-file salts, zeroization, constant-time operations
- **Performance**: High performance with streaming I/O, parallelization, hardware acceleration
- **Architecture**: Vertical slicing by use case with shared cryptographic primitives

### 1.2 File Header Format
```
[Magic: 4 bytes = "ENC2"]
[Version: 2 bytes = 2]
[Salt: 16 bytes]
[IV: 16 bytes]
[Directory Path Length: 2 bytes]          // NEW: For directory restoration
[Encrypted Directory Path: variable]      // NEW: Original directory structure
[Directory Path HMAC: 32 bytes]          // NEW: HMAC of encrypted path
[Filename Length: 2 bytes]
[Encrypted Filename: variable length]
[Filename HMAC: 32 bytes]
[Metadata Length: 2 bytes]               // NEW: File permissions, timestamps
[Encrypted Metadata: variable]           // NEW: For restoration
[Metadata HMAC: 32 bytes]               // NEW: HMAC of encrypted metadata
[Encrypted Content: variable length]
[Content HMAC: 32 bytes]
```

**Header Enhancements:**
- Added directory path storage for structure restoration
- Added metadata storage for permissions/timestamps
- Each new field has its own HMAC for integrity
- Backward compatibility through version field

## 2. Core Data Structures & Shared Components

### 2.1 File Header Format Implementation
```rust
struct Header {
    magic: [u8; 4],              // "ENC2"
    version: u16,                // Version 2
    salt: [u8; 16],              // Unique per file
    iv: [u8; 16],                // Unique per file
    directory_path_length: u16,  // Length of encrypted directory path
    encrypted_directory_path: Vec<u8>,  // Original directory structure
    directory_path_hmac: [u8; 32],      // HMAC of encrypted path
    filename_length: u16,        // Length of encrypted filename
    encrypted_filename: Vec<u8>, // Original filename (encrypted)
    filename_hmac: [u8; 32],     // HMAC of encrypted filename
    metadata_length: u16,        // Length of encrypted metadata
    encrypted_metadata: Vec<u8>, // File permissions, timestamps
    metadata_hmac: [u8; 32],     // HMAC of encrypted metadata
    // Followed by encrypted content and content HMAC
}

impl Header {
    fn serialize(&self) -> Vec<u8> { /* ... */ }
    fn deserialize(data: &[u8]) -> Result<(Header, usize), Error> { /* ... */ }
    fn validate_magic(&self) -> bool { self.magic == b"ENC2" }
}
```

### 2.2 Shared Cryptographic Primitives
```rust
// In shared/crypto/
struct KeyMaterial {
    encryption_key: SecretVec<u8>,    // 32 bytes, auto-zeroized
    hmac_key: SecretVec<u8>,         // 32 bytes, auto-zeroized
    obfuscation_key: SecretVec<u8>,  // 32 bytes for filename obfuscation
}

struct FileMetadata {
    permissions: u32,
    created: SystemTime,
    modified: SystemTime,
    accessed: SystemTime,
}

// Core crypto functions used across modules
fn derive_key_material(password: &str, salt: &[u8]) -> Result<KeyMaterial, Error>;
fn encrypt_aes_cbc(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Error>;
fn decrypt_aes_cbc(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Error>;
fn compute_hmac(key: &[u8], data: &[u8]) -> [u8; 32];
fn verify_hmac(key: &[u8], data: &[u8], expected: &[u8]) -> bool;
```

### 2.3 Error Handling
```rust
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Cryptographic operation failed: {0}")]
    CryptographicError(String),
    
    #[error("File system error: {0}")]
    FileSystemError(#[from] std::io::Error),
    
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("Header parsing failed: {0}")]
    HeaderParsingError(String),
    
    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),
    
    #[error("Invalid file format")]
    InvalidFileFormat,
    
    #[error("File not found: {0}")]
    FileNotFound(String),
}
```

## 3. Use Case Implementations

### 3.1 File Encryption (encryption/ module)
```rust
// encryption/encrypt_file.rs
pub fn encrypt_single_file(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    obfuscate_filename: bool
) -> Result<(), CryptoError> {
    // 1. Generate salt and IV
    // 2. Derive key material from password
    // 3. Read file content and metadata
    // 4. Encrypt content with AES-CBC
    // 5. Create and serialize header
    // 6. Write encrypted file atomically
}

// encryption/filename_obfuscation.rs
pub fn obfuscate_filename(key: &[u8], original_name: &str) -> String {
    // HMAC-based collision-resistant obfuscation
}
```

### 3.2 File Decryption (decryption/ module)
```rust
// decryption/decrypt_file.rs
pub fn decrypt_single_file(
    input_path: &Path,
    output_path: &Path,
    password: &str
) -> Result<(), CryptoError> {
    // 1. Read and parse header
    // 2. Derive key material from password and header salt
    // 3. Verify HMAC authentication
    // 4. Decrypt content with AES-CBC
    // 5. Restore original filename and metadata
    // 6. Write decrypted file atomically
}

// decryption/filename_restoration.rs
pub fn restore_original_filename(
    header: &Header,
    keys: &KeyMaterial
) -> Result<String, CryptoError> {
    // Decrypt and verify filename from header
}
```

### 3.3 File Listing (listing/ module)
```rust
// listing/file_scanner.rs
pub fn list_encrypted_files(directory: &Path, password: &str) -> Result<Vec<FileInfo>, CryptoError> {
    // 1. Scan directory for files with "ENC2" magic
    // 2. Parse headers (no full decryption)
    // 3. Extract original filenames and metadata
    // 4. Return structured file information
}

pub struct FileInfo {
    pub original_name: String,
    pub encrypted_path: PathBuf,
    pub size: u64,
    pub modified: SystemTime,
}
```

### 3.4 Secure Viewing (viewing/ module)
```rust
// viewing/streaming_decrypt.rs
pub fn stream_decrypt_to_viewer(
    encrypted_path: &Path,
    password: &str,
    viewer_command: Option<&str>
) -> Result<(), CryptoError> {
    // 1. Create secure temporary file
    // 2. Stream decrypt to temporary file
    // 3. Launch viewer with temporary file
    // 4. Clean up on exit
}
```

### 3.5 Secure Editing (editing/ module)
```rust
// editing/atomic_updates.rs
pub fn edit_encrypted_file(
    encrypted_path: &Path,
    password: &str,
    editor_command: Option<&str>
) -> Result<(), CryptoError> {
    // 1. Decrypt to secure temporary file
    // 2. Launch editor with temporary file
    // 3. Re-encrypt modified content
    // 4. Atomically replace original file
}
```

## 4. Security Enhancements

### 4.1 Enhanced Cryptographic Security
- **Constant-time operations**: All HMAC comparisons use constant-time functions
- **Memory protection**: All sensitive data uses `SecretVec` with automatic zeroization
- **Key stretching**: Argon2id with memory-hard parameters (m=64MiB, t=3, p=4)
- **IV management**: Cryptographically secure random IVs per file
- **HMAC coverage**: Each data section has individual HMAC protection

### 4.2 Filename Obfuscation Security
```rust
// In encryption/filename_obfuscation.rs
pub fn obfuscate_name_with_collision_check(
    key: &[u8], 
    name: &str, 
    existing_names: &HashSet<String>
) -> Result<String, CryptoError> {
    let mut counter = 0u32;
    loop {
        let input = if counter == 0 {
            name.to_string()
        } else {
            format!("{}_{}", name, counter)
        };
        
        let hmac = compute_hmac(key, input.as_bytes());
        let obfuscated = base64::encode_config(&hmac[..20], base64::URL_SAFE_NO_PAD);
        
        if !existing_names.contains(&obfuscated) {
            return Ok(obfuscated);
        }
        
        counter += 1;
        if counter > 1000 {
            return Err(CryptoError::TooManyCollisions);
        }
    }
}
```

### 4.3 Side-channel Mitigation
- **Timing attack protection**: Constant-time HMAC verification
- **Memory access patterns**: Avoid data-dependent memory access
- **Error uniformity**: All authentication failures return the same error type
- **Key derivation protection**: Use timing-consistent Argon2 parameters

## 5. Performance Optimizations

### 5.1 Streaming and Buffering
```rust
// In shared/crypto/streaming.rs
const OPTIMAL_BUFFER_SIZE: usize = 64 * 1024; // 64KB buffers
const SMALL_FILE_THRESHOLD: usize = 1024 * 1024; // 1MB threshold for batching

pub fn encrypt_with_optimal_buffering(
    input: &mut dyn Read, 
    output: &mut dyn Write,
    key: &[u8],
    iv: &[u8]
) -> Result<(), CryptoError> {
    let mut buffer = vec![0u8; OPTIMAL_BUFFER_SIZE];
    let mut cipher = create_aes_cipher(key, iv);
    
    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 { break; }
        
        let encrypted = cipher.update(&buffer[..bytes_read])?;
        output.write_all(&encrypted)?;
    }
    
    let final_block = cipher.finalize()?;
    output.write_all(&final_block)?;
    Ok(())
}
```

### 5.2 Parallel Processing
```rust
// In encryption/encrypt_directory.rs
use rayon::prelude::*;

pub fn encrypt_directory_parallel(
    files: Vec<PathBuf>, 
    password: &str,
    output_dir: &Path,
    obfuscate: bool
) -> Result<(), CryptoError> {
    let errors: Vec<_> = files
        .par_iter()
        .map(|file_path| {
            encrypt_single_file(file_path, output_dir, password, obfuscate)
        })
        .filter_map(|result| result.err())
        .collect();
        
    if !errors.is_empty() {
        return Err(CryptoError::BatchProcessingFailed(errors));
    }
    
    Ok(())
}
```

### 5.3 Session Key Caching
```rust
// In shared/crypto/key_cache.rs
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

pub struct SessionKeyCache {
    cache: Arc<RwLock<HashMap<String, CachedKey>>>,
    max_age: Duration,
}

struct CachedKey {
    key_material: KeyMaterial,
    cache_until: Instant,
}

impl SessionKeyCache {
    pub fn get_or_derive(
        &self, 
        password: &str, 
        salt: &[u8]
    ) -> Result<KeyMaterial, CryptoError> {
        let cache_key = self.compute_cache_key(password, salt);
        
        // Try to get from cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(cached_key) = cache.get(&cache_key) {
                if cached_key.cache_until > Instant::now() {
                    return Ok(cached_key.key_material.clone());
                }
            }
        }
        
        // Derive new key and cache it
        let key_material = derive_key_material(password, salt)?;
        let cached_key = CachedKey {
            key_material: key_material.clone(),
            cache_until: Instant::now() + self.max_age,
        };
        
        {
            let mut cache = self.cache.write().unwrap();
            cache.insert(cache_key, cached_key);
        }
        
        Ok(key_material)
    }
}
```

## 6. Error Handling and Recovery

### 6.1 Comprehensive Error Types
```rust
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Cryptographic operation failed: {0}")]
    CryptographicError(String),
    
    #[error("File system error: {0}")]
    FileSystemError(#[from] std::io::Error),
    
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("Header parsing failed: {0}")]
    HeaderParsingError(String),
    
    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),
    
    #[error("Filename collision limit exceeded")]
    TooManyCollisions,
    
    #[error("Invalid file format")]
    InvalidFileFormat,
    
    #[error("File not found: {0}")]
    FileNotFound(String),
    
    #[error("Operation interrupted: {context}")]
    OperationInterrupted { context: String },
    
    #[error("Batch processing failed: {0:?}")]
    BatchProcessingFailed(Vec<CryptoError>),
}
```

### 6.2 Recovery Mechanisms
```rust
// In shared/recovery.rs
pub struct RecoveryManager {
    transaction_log: PathBuf,
}

pub struct TransactionId(uuid::Uuid);

impl RecoveryManager {
    pub fn begin_transaction(&mut self, operation: &str) -> Result<TransactionId, CryptoError> {
        let tx_id = TransactionId(uuid::Uuid::new_v4());
        let entry = TransactionLogEntry {
            id: tx_id.0,
            operation: operation.to_string(),
            started_at: SystemTime::now(),
            completed: false,
            rollback_actions: Vec::new(),
        };
        
        self.write_log_entry(&entry)?;
        Ok(tx_id)
    }
    
    pub fn add_rollback_action(
        &mut self, 
        tx_id: TransactionId, 
        action: RollbackAction
    ) -> Result<(), CryptoError> {
        // Add action to transaction log for recovery
        Ok(())
    }
    
    pub fn commit_transaction(&mut self, tx_id: TransactionId) -> Result<(), CryptoError> {
        // Mark transaction as completed
        Ok(())
    }
    
    pub fn recover_interrupted_operations(&self) -> Result<(), CryptoError> {
        // Find incomplete transactions and roll them back
        Ok(())
    }
}
```

## 7. Testing Strategy

### 7.1 Unit Testing for Individual Modules
```rust
// Example: testing encryption module
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;
    
    #[test]
    fn test_single_file_encryption_roundtrip() {
        let temp_dir = tempdir().unwrap();
        let input_file = temp_dir.path().join("test.txt");
        let encrypted_file = temp_dir.path().join("test.txt.enc");
        let decrypted_file = temp_dir.path().join("test_decrypted.txt");
        
        // Create test file
        fs::write(&input_file, b"Hello, world!").unwrap();
        
        // Encrypt
        encrypt_single_file(&input_file, &encrypted_file, "password", false).unwrap();
        
        // Decrypt
        decrypt_single_file(&encrypted_file, &decrypted_file, "password").unwrap();
        
        // Verify
        let decrypted_content = fs::read(&decrypted_file).unwrap();
        assert_eq!(decrypted_content, b"Hello, world!");
    }
    
    #[test]
    fn test_filename_obfuscation() {
        let key = b"test_key_32_bytes_long_padding!!";
        let original_name = "secret_document.pdf";
        
        let obfuscated = obfuscate_filename(key, original_name).unwrap();
        assert_ne!(obfuscated, original_name);
        assert!(obfuscated.len() > 0);
    }
}
```

### 7.2 Property-Based Testing
```rust
// Testing crypto operations with proptest
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_encrypt_decrypt_roundtrip(
        data in any::<Vec<u8>>(), 
        password in "\\PC{8,50}"
    ) {
        let temp_dir = tempdir().unwrap();
        let input_file = temp_dir.path().join("input");
        let encrypted_file = temp_dir.path().join("encrypted");
        let output_file = temp_dir.path().join("output");
        
        // Write test data
        fs::write(&input_file, &data).unwrap();
        
        // Encrypt and decrypt
        encrypt_single_file(&input_file, &encrypted_file, &password, false).unwrap();
        decrypt_single_file(&encrypted_file, &output_file, &password).unwrap();
        
        // Verify roundtrip
        let result = fs::read(&output_file).unwrap();
        prop_assert_eq!(data, result);
    }
    
    #[test]
    fn test_filename_obfuscation_collision_resistance(
        names in prop::collection::vec("\\PC{1,100}", 1..100)
    ) {
        let key = b"test_key_32_bytes_long_padding!!";
        let mut obfuscated_names = HashSet::new();
        
        for name in names {
            let obfuscated = obfuscate_filename(key, &name).unwrap();
            prop_assert!(obfuscated_names.insert(obfuscated));
        }
    }
}
```

## 8. Code Organization & Architecture

### 8.1 Vertical Slicing by Use Case

The codebase is organized around distinct binaries with vertical slicing by use case, sharing common functionality through a library. This approach optimizes for:
- **Independent development** of each tool
- **Focused functionality** per binary
- **Optimized compilation** and binary sizes
- **Clear feature ownership**

### 8.2 Module Structure

```rust
src/
├── lib.rs                     // Public API for shared functionality
├── shared/                    // Core shared components
│   ├── mod.rs
│   ├── crypto/                // Cryptographic primitives
│   │   ├── mod.rs
│   │   ├── aes.rs
│   │   ├── hmac.rs
│   │   ├── argon2.rs
│   │   └── secure_memory.rs
│   ├── header.rs              // File header format
│   ├── file_detection.rs      // Detect encrypted files
│   └── errors.rs              // Common error types
├── encryption/                // Everything needed for lock binary
│   ├── mod.rs
│   ├── encrypt_file.rs
│   ├── encrypt_directory.rs
│   ├── filename_obfuscation.rs
│   └── cli.rs
├── decryption/                // Everything needed for unlock binary
│   ├── mod.rs
│   ├── decrypt_file.rs
│   ├── decrypt_directory.rs
│   ├── filename_restoration.rs
│   └── cli.rs
├── listing/                   // Everything needed for cryptls binary
│   ├── mod.rs
│   ├── file_scanner.rs
│   ├── metadata_extractor.rs
│   └── cli.rs
├── viewing/                   // Everything needed for cryptview binary
│   ├── mod.rs
│   ├── viewer_integration.rs
│   ├── streaming_decrypt.rs
│   └── cli.rs
├── editing/                   // Everything needed for cryptedit binary
│   ├── mod.rs
│   ├── editor_integration.rs
│   ├── atomic_updates.rs
│   └── cli.rs
└── bin/
    ├── lock.rs                // use crate::encryption
    ├── unlock.rs              // use crate::decryption
    ├── cryptls.rs             // use crate::listing
    ├── cryptview.rs           // use crate::viewing
    └── cryptedit.rs           // use crate::editing
```

### 8.3 Dependency Architecture

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│   lock      │  │   unlock    │  │  cryptls    │
│   binary    │  │   binary    │  │   binary    │
└─────────────┘  └─────────────┘  └─────────────┘
       │                │                │
       ▼                ▼                ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ encryption/ │  │ decryption/ │  │  listing/   │
│   module    │  │   module    │  │   module    │
└─────────────┘  └─────────────┘  └─────────────┘
       │                │                │
       └────────────────┼────────────────┘
                        ▼
                ┌─────────────┐
                │   shared/   │
                │   module    │
                └─────────────┘
```

### 8.4 Benefits of This Architecture

**Feature-Complete Modules**: Each module contains everything needed for its use case including business logic, file I/O, CLI handling, and specific error handling.

**Independent Development**: Work on `lock` without touching `unlock` code, add new features to `cryptview` without affecting other binaries, deploy/update binaries independently.

**Optimized Compilation**: Each binary only compiles what it needs, resulting in faster build times and smaller binary sizes.

**Clear Ownership**: Each feature has a clear "home" with no confusion about where code belongs and easy reasoning about dependencies.

## 9. Implementation Roadmap

### Phase 1: Set Up Module Structure
**Goal**: Organize codebase according to vertical slicing architecture
- Create `shared/`, `encryption/`, `decryption/`, `listing/` module directories
- Set up basic `mod.rs` files with proper module exports
- Update `lib.rs` to expose new module structure
- Move existing code into appropriate modules

### Phase 2: Complete Header Implementation  
**Goal**: Finish the file header format with full serialization
- Complete `Header` struct with all fields from design specification
- Implement serialization to bytes (write header to file)
- Implement deserialization from bytes (read header from file)
- Add header validation and magic number checking

### Phase 3: Implement Core Cryptographic Operations
**Goal**: Build secure crypto primitives in `shared/crypto/`
- Implement AES-256-CBC encryption/decryption
- Implement HMAC-SHA256 for authentication
- Implement Argon2id key derivation
- Add `SecretVec` for automatic memory zeroization

### Phase 4: Build Basic File Encryption
**Goal**: Create core encryption functionality in `encryption/` module
- Implement single file encryption with full header
- Add password-based key derivation
- Generate secure random salts and IVs per file
- Store file metadata (permissions, timestamps) in header

### Phase 5: Build Basic File Decryption
**Goal**: Create core decryption functionality in `decryption/` module  
- Implement single file decryption with header parsing
- Verify HMAC authentication before decryption
- Restore original file metadata after decryption
- Handle decryption errors gracefully

### Phase 6: Add Filename Obfuscation
**Goal**: Implement secure filename obfuscation in `encryption/` module
- Create HMAC-based filename obfuscation algorithm
- Add collision detection and resolution
- Store encrypted original filename in header
- Make obfuscation optional via CLI flag

### Phase 7: Add Filename Restoration  
**Goal**: Implement filename restoration in `decryption/` module
- Parse encrypted filename from header
- Decrypt and restore original filename
- Handle both obfuscated and non-obfuscated files
- Validate filename integrity with HMAC

### Phase 8: Build File Listing Capability
**Goal**: Create encrypted file listing in `listing/` module
- Implement header-only reading (no full decryption)
- Parse encrypted filenames and display original names
- Show file metadata (sizes, dates) from headers
- Handle directories with mixed encrypted/regular files

### Phase 9: Create `lock` Binary
**Goal**: Build CLI binary for file encryption
- Create `bin/lock.rs` with argument parsing
- Integrate with `encryption/` module
- Support single files with `--obfuscate` flag  
- Add basic error handling and user feedback

### Phase 10: Create `unlock` Binary
**Goal**: Build CLI binary for file decryption
- Create `bin/unlock.rs` with argument parsing
- Integrate with `decryption/` module
- Support single files with automatic format detection
- Add basic error handling and user feedback

### Phase 11: Create `cryptls` Binary
**Goal**: Build CLI binary for file listing
- Create `bin/cryptls.rs` with argument parsing
- Integrate with `listing/` module
- List encrypted files in directory with original names
- Display file information in user-friendly format

### Phase 12: Add Directory Support to `lock`
**Goal**: Extend encryption to handle directories
- Add directory traversal and recursive file discovery
- Flatten directory structure to single output directory
- Store original directory paths in each file header
- Handle multiple files with batch processing

### Phase 13: Add Directory Support to `unlock`
**Goal**: Extend decryption to handle directories
- Auto-detect encrypted files in directory
- Restore original directory structure from headers
- Handle batch decryption with error aggregation
- Skip non-encrypted files gracefully

### Phase 14: Add Multi-File Support
**Goal**: Support multiple file arguments in CLI binaries
- Update `lock` to accept multiple file/directory arguments
- Update `unlock` to handle multiple paths
- Add progress reporting for batch operations
- Implement session key caching for performance

### Phase 15: Add Secure Viewing (`cryptview`)
**Goal**: View encrypted files without persistent decryption
- Create `viewing/` module with streaming decryption
- Create `bin/cryptview.rs` for file viewing
- Integration with `$PAGER` and external viewers
- Secure temporary file handling with cleanup

### Phase 16: Add Secure Editing (`cryptedit`)
**Goal**: Edit encrypted text files in-place
- Create `editing/` module with atomic file updates
- Create `bin/cryptedit.rs` for text file editing
- Integration with `$EDITOR` and external editors
- Backup and rollback functionality

### Phase 17: Performance Optimization
**Goal**: Optimize for production use
- Add parallel processing with `rayon`
- Implement streaming I/O for large files
- Add session key caching
- Memory usage optimization and profiling

### Phase 18: Comprehensive Testing
**Goal**: Ensure reliability and security
- Unit tests for all crypto operations
- Integration tests for all CLI binaries
- Property-based testing for edge cases
- Security testing and memory safety validation

### Phase 19: Documentation and Polish
**Goal**: Prepare for release
- Add comprehensive CLI help and man pages
- Create usage examples and tutorials
- Code review and refactoring
- Cross-platform compatibility testing

### Phase 20: Release Preparation
**Goal**: Package and distribute
- Set up CI/CD pipeline
- Create release packages for multiple platforms
- Security audit and penetration testing
- Release notes and migration guides

## 10. Conclusion

This comprehensive design provides a robust foundation for a high-security, high-performance file encryption system. The vertical slicing architecture with separate binaries supports focused development while maintaining security best practices and performance optimization opportunities. The complete header format and shared cryptographic primitives provide a solid foundation for all use cases.

Key strengths of this design:
- **Security**: Multiple layers of protection with proven cryptographic primitives
- **Simplicity**: Clean, Unix-style binaries (`lock`, `unlock`, `cryptls`, `cryptview`, `cryptedit`)
- **Usability**: Intuitive CLI with smart defaults and optional filename obfuscation  
- **Maintainability**: Clear separation by use case with shared cryptographic core
- **Extensibility**: Modular architecture allows independent feature development
- **Performance**: Optimized for single-purpose tools with streaming I/O

The granular implementation roadmap provides a clear path to delivery with 20 focused phases, ensuring thorough testing and validation at each step while avoiding overwhelming complexity for development agents.
