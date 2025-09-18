# File Encryption Program: Comprehensive Design Specification

## Executive Summary

This document presents a comprehensive design for a high-security, high-performance file encryption program written in Rust. The system supports single file and directory encryption with reversible filename obfuscation, advanced features like partial decryption, and maintains extreme security through proven cryptographic primitives and careful implementation practices.

## 1. Core Requirements & Architecture

### 1.1 Fundamental Requirements
- **Encryption**: Single files and directories (recursive) using AES-256-CBC + HMAC-SHA256
- **Filename Obfuscation**: Reversible, no manifest required
- **Security**: Extreme security with per-file salts, zeroization, constant-time operations
- **Performance**: High performance with streaming I/O, parallelization, hardware acceleration
- **Architecture**: Dependency Inversion Principle (DIP) for modularity and testability

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

## 2. Enhanced Component Architecture

### 2.1 Key Management Trait
```rust
trait KeyDeriver {
    fn derive_key(&self, password: &str, salt: &[u8]) -> Result<KeyMaterial, Error>;
    fn derive_session_key(&self, password: &str) -> Result<SessionKey, Error>; // NEW
}

struct KeyMaterial {
    encryption_key: SecretVec<u8>,    // 32 bytes, auto-zeroized
    hmac_key: SecretVec<u8>,         // 32 bytes, auto-zeroized
    obfuscation_key: SecretVec<u8>,  // 32 bytes for filename obfuscation
}

struct SessionKey {
    key_material: KeyMaterial,
    salt: [u8; 16],
    cache_until: Instant,            // For session-based key caching
}
```

### 2.2 Enhanced Encryption Trait
```rust
trait Encryptor {
    // Core encryption/decryption
    fn encrypt(&self, keys: &KeyMaterial, plaintext: &mut dyn Read, 
               output: &mut dyn Write, iv: &[u8]) -> Result<Vec<u8>, Error>;
    
    fn decrypt(&self, keys: &KeyMaterial, ciphertext: &mut dyn Read, 
               output: &mut dyn Write, iv: &[u8], hmac: &[u8]) -> Result<(), Error>;
    
    // Partial decryption for advanced features
    fn decrypt_range(&self, keys: &KeyMaterial, ciphertext: &mut dyn Read,
                     output: &mut dyn Write, start_byte: u64, length: u64) -> Result<(), Error>;
    
    // Filename handling
    fn encrypt_name(&self, keys: &KeyMaterial, name: &str, path: &Path) 
                   -> Result<(Vec<u8>, Vec<u8>), Error>;
    
    fn obfuscate_name(&self, key: &[u8], name: &str, path: &Path) -> Result<String, Error>;
    
    fn deobfuscate_name(&self, keys: &KeyMaterial, obfuscated: &str, path: &Path,
                       ciphertext: &[u8], hmac: &[u8]) -> Result<String, Error>;
    
    // Directory and metadata handling
    fn encrypt_directory_path(&self, keys: &KeyMaterial, path: &Path) 
                             -> Result<(Vec<u8>, Vec<u8>), Error>;
    
    fn encrypt_metadata(&self, keys: &KeyMaterial, metadata: &FileMetadata)
                       -> Result<(Vec<u8>, Vec<u8>), Error>;
}
```

### 2.3 Enhanced File System Trait
```rust
trait FileSystem {
    // Basic operations
    fn read_file(&self, path: &Path) -> Result<Box<dyn Read>, Error>;
    fn write_file(&self, path: &Path, content: &mut dyn Read) -> Result<(), Error>;
    fn traverse_directory(&self, root: &Path, recursive: bool) -> Result<Vec<PathBuf>, Error>;
    
    // Enhanced operations
    fn read_file_range(&self, path: &Path, start: u64, length: u64) 
                      -> Result<Box<dyn Read>, Error>;
    
    fn write_encrypted_file(&self, path: &Path, header: Header, content: &mut dyn Read)
                           -> Result<(), Error>;
    
    fn read_encrypted_file(&self, path: &Path) -> Result<(Header, Box<dyn Read>), Error>;
    
    fn read_header_only(&self, path: &Path) -> Result<Header, Error>; // For listing
    
    fn get_file_metadata(&self, path: &Path) -> Result<FileMetadata, Error>;
    fn set_file_metadata(&self, path: &Path, metadata: &FileMetadata) -> Result<(), Error>;
    
    // Atomic operations
    fn atomic_write(&self, path: &Path, content: &mut dyn Read) -> Result<(), Error>;
    fn atomic_rename(&self, old: &Path, new: &Path) -> Result<(), Error>;
}

struct FileMetadata {
    permissions: u32,
    created: SystemTime,
    modified: SystemTime,
    accessed: SystemTime,
}
```

### 2.4 New Traits for Advanced Features

```rust
trait PartialDecryptor {
    fn decrypt_to_stream(&self, encrypted_path: &Path, keys: &KeyMaterial,
                        output: &mut dyn Write) -> Result<(), Error>;
    
    fn decrypt_range_to_stream(&self, encrypted_path: &Path, keys: &KeyMaterial,
                              start: u64, length: u64, output: &mut dyn Write) 
                              -> Result<(), Error>;
}

trait FileEditor {
    fn edit_text_file(&self, encrypted_path: &Path, keys: &KeyMaterial,
                     editor_command: &str) -> Result<(), Error>;
    
    fn get_editable_content(&self, encrypted_path: &Path, keys: &KeyMaterial)
                           -> Result<String, Error>;
    
    fn save_edited_content(&self, encrypted_path: &Path, keys: &KeyMaterial,
                          content: &str) -> Result<(), Error>;
}

trait FileViewer {
    fn view_file(&self, encrypted_path: &Path, keys: &KeyMaterial,
                viewer_command: &str) -> Result<(), Error>;
    
    fn get_file_preview(&self, encrypted_path: &Path, keys: &KeyMaterial,
                       preview_size: usize) -> Result<Vec<u8>, Error>;
}

trait FileLister {
    fn list_encrypted_names(&self, directory: &Path, keys: &KeyMaterial)
                           -> Result<Vec<FileInfo>, Error>;
    
    fn get_original_name(&self, encrypted_path: &Path, keys: &KeyMaterial)
                        -> Result<String, Error>;
}

struct FileInfo {
    original_name: String,
    obfuscated_name: String,
    original_path: PathBuf,
    size: u64,
    encrypted_size: u64,
    modified: SystemTime,
}
```

## 3. Feature Implementation Specifications

### 3.1 Core Encryption Features

#### Single File Encryption
- Generate unique salt and IV per file
- Derive keys using Argon2id
- Encrypt filename and content separately
- Store original metadata for restoration
- Use atomic file operations to prevent corruption

#### Multiple File Encryption
- Process files in parallel using `rayon`
- Share session keys for performance
- Batch small files to reduce overhead
- Maintain transaction log for rollback capability

#### Directory Encryption with Structure Collapse
- Traverse directory recursively
- Store full original path in each file header
- Flatten all files to single directory
- Generate collision-resistant obfuscated names
- Preserve directory metadata separately

### 3.2 Advanced Features

#### Filename Listing Without Full Decryption
```rust
impl FileLister for EncryptionService {
    fn list_encrypted_names(&self, directory: &Path, keys: &KeyMaterial)
                           -> Result<Vec<FileInfo>, Error> {
        let mut file_infos = Vec::new();
        
        for entry in std::fs::read_dir(directory)? {
            let path = entry?.path();
            if let Ok(header) = self.file_system.read_header_only(&path) {
                let original_name = self.encryptor.deobfuscate_name(
                    keys, &path.file_name().unwrap().to_string_lossy(),
                    &path, &header.encrypted_filename, &header.filename_hmac
                )?;
                
                file_infos.push(FileInfo {
                    original_name,
                    obfuscated_name: path.file_name().unwrap().to_string_lossy().to_string(),
                    original_path: self.decrypt_directory_path(&header, keys)?,
                    size: self.calculate_original_size(&header)?,
                    encrypted_size: std::fs::metadata(&path)?.len(),
                    modified: std::fs::metadata(&path)?.modified()?,
                });
            }
        }
        
        Ok(file_infos)
    }
}
```

#### Text File Editing Without Full Decryption
```rust
impl FileEditor for EncryptionService {
    fn edit_text_file(&self, encrypted_path: &Path, keys: &KeyMaterial,
                     editor_command: &str) -> Result<(), Error> {
        // Create temporary file
        let temp_file = tempfile::NamedTempFile::new()?;
        
        // Decrypt to temporary file
        let mut temp_writer = BufWriter::new(temp_file.as_file());
        self.partial_decryptor.decrypt_to_stream(encrypted_path, keys, &mut temp_writer)?;
        temp_writer.flush()?;
        
        // Launch editor
        let output = Command::new(editor_command)
            .arg(temp_file.path())
            .status()?;
            
        if !output.success() {
            return Err(Error::EditorFailed);
        }
        
        // Re-encrypt the modified content
        let mut temp_reader = BufReader::new(File::open(temp_file.path())?);
        self.encrypt_file_in_place(encrypted_path, &mut temp_reader, keys)?;
        
        // Temporary file is automatically cleaned up
        Ok(())
    }
}
```

#### File Viewing Without Full Decryption
```rust
impl FileViewer for EncryptionService {
    fn view_file(&self, encrypted_path: &Path, keys: &KeyMaterial,
                viewer_command: &str) -> Result<(), Error> {
        // Create named pipe or temporary file
        let temp_file = tempfile::NamedTempFile::new()?;
        
        // Decrypt content to temporary file
        let mut temp_writer = BufWriter::new(temp_file.as_file());
        self.partial_decryptor.decrypt_to_stream(encrypted_path, keys, &mut temp_writer)?;
        temp_writer.flush()?;
        
        // Launch viewer
        Command::new(viewer_command)
            .arg(temp_file.path())
            .status()?;
        
        Ok(())
    }
    
    fn get_file_preview(&self, encrypted_path: &Path, keys: &KeyMaterial,
                       preview_size: usize) -> Result<Vec<u8>, Error> {
        let mut preview_buffer = Vec::with_capacity(preview_size);
        let mut cursor = Cursor::new(&mut preview_buffer);
        
        self.partial_decryptor.decrypt_range_to_stream(
            encrypted_path, keys, 0, preview_size as u64, &mut cursor
        )?;
        
        Ok(preview_buffer)
    }
}
```

### 3.3 Directory Structure Restoration
```rust
impl EncryptionService {
    fn decrypt_directory(&self, encrypted_dir: &Path, output_dir: &Path, 
                        keys: &KeyMaterial, restore_structure: bool) -> Result<(), Error> {
        let file_infos = self.list_encrypted_names(encrypted_dir, keys)?;
        
        for file_info in file_infos {
            let encrypted_path = encrypted_dir.join(&file_info.obfuscated_name);
            
            let output_path = if restore_structure {
                output_dir.join(&file_info.original_path)
            } else {
                output_dir.join(&file_info.original_name)
            };
            
            // Create parent directories if needed
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            
            // Decrypt file
            self.decrypt_file(&encrypted_path, &output_path, keys)?;
            
            // Restore metadata
            if let Ok(metadata) = self.decrypt_file_metadata(&encrypted_path, keys) {
                self.file_system.set_file_metadata(&output_path, &metadata)?;
            }
        }
        
        Ok(())
    }
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
impl EnhancedObfuscation {
    fn obfuscate_name_with_collision_check(&self, key: &[u8], name: &str, 
                                          path: &Path, existing_names: &HashSet<String>) 
                                          -> Result<String, Error> {
        let mut counter = 0u32;
        loop {
            let input = if counter == 0 {
                name.to_string()
            } else {
                format!("{}_{}", name, counter)
            };
            
            let hmac = self.compute_hmac(key, input.as_bytes());
            let obfuscated = base64::encode_config(&hmac[..20], base64::URL_SAFE_NO_PAD);
            
            if !existing_names.contains(&obfuscated) {
                return Ok(obfuscated);
            }
            
            counter += 1;
            if counter > 1000 {
                return Err(Error::TooManyCollisions);
            }
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
const OPTIMAL_BUFFER_SIZE: usize = 64 * 1024; // 64KB buffers
const SMALL_FILE_THRESHOLD: usize = 1024 * 1024; // 1MB threshold for batching

impl PerformanceOptimizations {
    fn encrypt_with_optimal_buffering(&self, input: &mut dyn Read, 
                                     output: &mut dyn Write) -> Result<(), Error> {
        let mut buffer = vec![0u8; OPTIMAL_BUFFER_SIZE];
        let mut cipher = self.create_cipher();
        
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
}
```

### 5.2 Parallel Processing
```rust
use rayon::prelude::*;

impl ParallelProcessing {
    fn encrypt_directory_parallel(&self, files: Vec<PathBuf>, keys: Arc<KeyMaterial>)
                                 -> Result<(), Error> {
        let errors: Vec<_> = files
            .par_iter()
            .map(|file_path| {
                self.encrypt_single_file(file_path, &keys)
            })
            .filter_map(|result| result.err())
            .collect();
            
        if !errors.is_empty() {
            return Err(Error::BatchProcessingFailed(errors));
        }
        
        Ok(())
    }
}
```

### 5.3 Session Key Caching
```rust
struct SessionKeyCache {
    cache: Arc<RwLock<HashMap<String, SessionKey>>>,
    max_age: Duration,
}

impl SessionKeyCache {
    fn get_or_derive(&self, password: &str, salt: &[u8], 
                    deriver: &dyn KeyDeriver) -> Result<KeyMaterial, Error> {
        let cache_key = self.compute_cache_key(password, salt);
        
        // Try to get from cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(session_key) = cache.get(&cache_key) {
                if session_key.cache_until > Instant::now() {
                    return Ok(session_key.key_material.clone());
                }
            }
        }
        
        // Derive new key and cache it
        let key_material = deriver.derive_key(password, salt)?;
        let session_key = SessionKey {
            key_material: key_material.clone(),
            cache_until: Instant::now() + self.max_age,
        };
        
        {
            let mut cache = self.cache.write().unwrap();
            cache.insert(cache_key, session_key);
        }
        
        Ok(key_material)
    }
}
```

## 6. Error Handling and Recovery

### 6.1 Comprehensive Error Types
```rust
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
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
    
    #[error("Partial decryption not supported for this file type")]
    PartialDecryptionNotSupported,
    
    #[error("Operation interrupted: {context}")]
    OperationInterrupted { context: String },
    
    #[error("Batch processing failed: {0:?}")]
    BatchProcessingFailed(Vec<EncryptionError>),
}
```

### 6.2 Recovery Mechanisms
```rust
struct RecoveryManager {
    transaction_log: PathBuf,
}

impl RecoveryManager {
    fn begin_transaction(&mut self, operation: &str) -> Result<TransactionId, Error> {
        let tx_id = TransactionId::new();
        let entry = TransactionLogEntry {
            id: tx_id,
            operation: operation.to_string(),
            started_at: SystemTime::now(),
            completed: false,
            rollback_actions: Vec::new(),
        };
        
        self.write_log_entry(&entry)?;
        Ok(tx_id)
    }
    
    fn add_rollback_action(&mut self, tx_id: TransactionId, action: RollbackAction) 
                          -> Result<(), Error> {
        // Add action to transaction log for recovery
        Ok(())
    }
    
    fn commit_transaction(&mut self, tx_id: TransactionId) -> Result<(), Error> {
        // Mark transaction as completed
        Ok(())
    }
    
    fn recover_interrupted_operations(&self) -> Result<(), Error> {
        // Find incomplete transactions and roll them back
        Ok(())
    }
}
```

## 7. Testing Strategy

### 7.1 Unit Testing with Mocks
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    
    mock! {
        FileSystem {}
        
        impl FileSystem for FileSystem {
            fn read_file(&self, path: &Path) -> Result<Box<dyn Read>, Error>;
            fn write_file(&self, path: &Path, content: &mut dyn Read) -> Result<(), Error>;
            // ... other methods
        }
    }
    
    #[test]
    fn test_single_file_encryption() {
        let mut mock_fs = MockFileSystem::new();
        mock_fs.expect_read_file()
            .returning(|_| Ok(Box::new(Cursor::new(b"test content"))));
        
        let encryptor = create_test_encryptor(mock_fs);
        let result = encryptor.encrypt_file("test.txt", "password");
        
        assert!(result.is_ok());
    }
}
```

### 7.2 Property-Based Testing
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_encrypt_decrypt_roundtrip(data in any::<Vec<u8>>(), password in "\\PC*") {
        let encryptor = create_test_encryptor();
        let encrypted = encryptor.encrypt(&data, &password)?;
        let decrypted = encryptor.decrypt(&encrypted, &password)?;
        
        prop_assert_eq!(data, decrypted);
    }
    
    #[test]
    fn test_filename_obfuscation_collision_resistance(
        names in prop::collection::vec("\\PC{1,100}", 1..1000)
    ) {
        let encryptor = create_test_encryptor();
        let mut obfuscated_names = HashSet::new();
        
        for name in names {
            let obfuscated = encryptor.obfuscate_name(&[0u8; 32], &name, Path::new("/"))?;
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

This comprehensive design provides a robust foundation for a high-security, high-performance file encryption system. The modular architecture supports all required features while maintaining security best practices and performance optimization opportunities. The enhanced header format and trait system provide extensibility for future requirements while maintaining backward compatibility.

Key strengths of this design:
- **Security**: Multiple layers of protection with proven cryptographic primitives
- **Performance**: Streaming I/O, parallel processing, and session key caching
- **Usability**: Advanced features like partial decryption and in-place editing
- **Maintainability**: Clear separation of concerns with dependency inversion
- **Extensibility**: Trait-based architecture supports future enhancements

The implementation roadmap provides a clear path to delivery while ensuring thorough testing and security validation at each phase.
