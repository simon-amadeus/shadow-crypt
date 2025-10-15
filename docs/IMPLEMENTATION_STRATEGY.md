# Shadow Implementation Strategy
## Functional Core, Imperative Shell Architecture

**Document Version**: 1.0  
**Date**: October 16, 2025  
**Based on**: SHADOW_SPECIFICATION_v1.0.md

---

## 1. Architecture Overview

This implementation strategy applies the **Functional Core, Imperative Shell** pattern to create a maintainable, testable, and secure Shadow encryption tool.

### 1.1 Pattern Benefits for Shadow
- **Testability**: Pure functions are easy to unit test
- **Security**: Cryptographic functions isolated from side effects
- **Reliability**: Immutable data reduces state-related bugs
- **Maintainability**: Clear separation of concerns

### 1.2 Architecture Layers

```
┌─────────────────────────────────────────┐
│              Imperative Shell            │
│  CLI • File I/O • Progress • Error UI   │
├─────────────────────────────────────────┤
│              Functional Core             │
│  Crypto • Validation • Data Transform   │
└─────────────────────────────────────────┘
```

---

## 2. Functional Core Design

### 2.1 Core Types (Pure Data)

```rust
// Secure string wrapper to encapsulate zeroize dependency
#[derive(Debug)]
pub struct SecureString(zeroize::Zeroizing<String>);

impl SecureString {
    pub fn new(s: String) -> Self {
        Self(zeroize::Zeroizing::new(s))
    }
    
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
    
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Clone for SecureString {
    fn clone(&self) -> Self {
        Self::new(self.0.as_str().to_string())
    }
}

// Secure key wrapper for cryptographic keys
#[derive(Debug, Clone)]
pub struct SecureKey(zeroize::Zeroizing<[u8; 32]>);

impl SecureKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(zeroize::Zeroizing::new(key))
    }
    
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// Secure bytes for sensitive data like nonces and salts (when needed to be stored)
#[derive(Debug, Clone)]
pub struct SecureBytes(zeroize::Zeroizing<Vec<u8>>);

impl SecureBytes {
    pub fn new(data: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(data))
    }
    
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

// Core domain types - immutable and serializable
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub original_name: String,
    pub content_hash: [u8; 32],  // SHA-256
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct EncryptionRequest {
    pub content: Vec<u8>,
    pub metadata: FileMetadata,
    pub password: SecureString,
    pub obfuscate_filename: bool,
}

#[derive(Debug, Clone)]
pub struct EncryptedFile {
    pub header: FileHeader,
    pub ciphertext: Vec<u8>,
    pub suggested_filename: String,
}

#[derive(Debug, Clone)]
pub struct FileHeader {
    pub magic: [u8; 8],          // "SHADOW01"
    pub algorithm_id: u8,        // 0x01
    pub obfuscation_flag: u8,    // 0x00 or 0x01
    pub content_hash: [u8; 32],
    pub filename_data: FilenameData,
    pub salt: [u8; 16],
    pub content_nonce: [u8; 24],
}

#[derive(Debug, Clone)]
pub enum FilenameData {
    Plaintext(String),
    Encrypted {
        ciphertext: Vec<u8>,
        nonce: [u8; 24],
    },
}
```

### 2.2 Pure Cryptographic Functions

```rust
// All functions pure - no side effects, deterministic with same inputs
pub mod crypto {
    use super::*;
    
    // Key derivation - pure function
    pub fn derive_key(password: &SecureString, salt: &[u8; 16]) -> Result<SecureKey, CryptoError> {
        // Argon2id implementation using password.as_str()
        // Returns SecureKey that will be zeroized when dropped
    }
    
    // Content encryption - pure function  
    pub fn encrypt_content(
        plaintext: &[u8],
        key: &SecureKey,
        nonce: &[u8; 24],
        aad: &[u8], // header as associated data
    ) -> Result<Vec<u8>, CryptoError> {
        // XChaCha20-Poly1305 implementation using key.as_bytes()
    }
    
    // Filename encryption - pure function
    pub fn encrypt_filename(
        filename: &str,
        master_key: &SecureKey,
        nonce: &[u8; 24],
    ) -> Result<Vec<u8>, CryptoError> {
        // HKDF derive filename key, then encrypt
        // Derived key should be zeroized after use
        let filename_key = SecureKey::new(hkdf_derive(master_key.as_bytes(), b"filename")?);
        // filename_key is automatically zeroized when it goes out of scope
        encrypt_with_key(filename.as_bytes(), &filename_key, nonce)
    }
    
    // Example helper function showing proper key handling
    fn hkdf_derive(master_key: &[u8; 32], info: &[u8]) -> Result<[u8; 32], CryptoError> {
        // Implementation that returns raw key bytes
        // Caller should wrap in SecureKey immediately
    }
    
    // Content hashing - pure function
    pub fn hash_content(content: &[u8]) -> [u8; 32] {
        // SHA-256 implementation
    }
    
    // Random generation - pure with external entropy
    pub fn generate_nonce() -> [u8; 24] {
        // Cryptographically secure random
    }
    
    pub fn generate_salt() -> [u8; 16] {
        // Cryptographically secure random
    }
}
```

### 2.3 Pure Validation Functions

```rust
pub mod validation {
    use super::*;
    
    // Input validation - pure functions
    pub fn validate_encryption_request(req: &EncryptionRequest) -> Result<(), ValidationError> {
        if req.password.is_empty() {
            return Err(ValidationError::EmptyPassword);
        }
        if req.content.is_empty() {
            return Err(ValidationError::EmptyFile);
        }
        Ok(())
    }
    
    pub fn validate_file_header(header: &[u8]) -> Result<FileHeader, ValidationError> {
        // Parse and validate header structure
    }
    
    pub fn check_content_duplicate(
        content_hash: &[u8; 32],
        existing_hashes: &[[u8; 32]],
    ) -> bool {
        existing_hashes.contains(content_hash)
    }
}
```

### 2.4 Pure Data Transformation Functions

```rust
pub mod transform {
    use super::*;
    
    // File processing pipeline - pure functions
    pub fn create_encryption_request(
        content: Vec<u8>,
        original_filename: String,
        password: SecureString,
        obfuscate: bool,
    ) -> EncryptionRequest {
        let content_hash = crypto::hash_content(&content);
        let metadata = FileMetadata {
            original_name: original_filename,
            content_hash,
            size: content.len() as u64,
        };
        
        EncryptionRequest {
            content,
            metadata,
            password,
            obfuscate_filename: obfuscate,
        }
    }
    
    // Main encryption pipeline - pure function
    pub fn encrypt_file(request: EncryptionRequest) -> Result<EncryptedFile, EncryptionError> {
        // 1. Generate random values
        let salt = crypto::generate_salt();
        let content_nonce = crypto::generate_nonce();
        let filename_nonce = if request.obfuscate_filename {
            Some(crypto::generate_nonce())
        } else {
            None
        };
        
        // 2. Derive key
        let master_key = crypto::derive_key(&request.password, &salt)?;
        
        // 3. Create filename data
        let filename_data = match request.obfuscate_filename {
            false => FilenameData::Plaintext(request.metadata.original_name.clone()),
            true => {
                let nonce = filename_nonce.unwrap();
                let encrypted = crypto::encrypt_filename(
                    &request.metadata.original_name,
                    &master_key,
                    &nonce,
                )?;
                FilenameData::Encrypted {
                    ciphertext: encrypted,
                    nonce,
                }
            }
        };
        
        // 4. Create header
        let header = FileHeader {
            magic: *b"SHADOW01",
            algorithm_id: 0x01,
            obfuscation_flag: if request.obfuscate_filename { 0x01 } else { 0x00 },
            content_hash: request.metadata.content_hash,
            filename_data,
            salt,
            content_nonce,
        };
        
        // 5. Serialize header for AAD
        let header_bytes = serialize_header(&header)?;
        
        // 6. Encrypt content
        let ciphertext = crypto::encrypt_content(
            &request.content,
            &master_key,
            &content_nonce,
            &header_bytes,
        )?;
        
        // 7. Generate output filename
        let suggested_filename = if request.obfuscate_filename {
            generate_random_filename()
        } else {
            format!("{}.shadow", request.metadata.original_name)
        };
        
        Ok(EncryptedFile {
            header,
            ciphertext,
            suggested_filename,
        })
    }
    
    // Header serialization - pure function
    pub fn serialize_header(header: &FileHeader) -> Result<Vec<u8>, SerializationError> {
        // Binary serialization of header structure
    }
    
    // Complete file serialization - pure function
    pub fn serialize_encrypted_file(file: &EncryptedFile) -> Result<Vec<u8>, SerializationError> {
        let mut result = serialize_header(&file.header)?;
        result.extend_from_slice(&file.ciphertext);
        Ok(result)
    }
    
    // Random filename generation - pure with external randomness
    fn generate_random_filename() -> String {
        // UUIDv4 format: a1b2c3d4-e5f6-7890-abcd-ef1234567890.shadow
        use uuid::Uuid;
        format!("{}.shadow", Uuid::new_v4())
    }
}
```

---

## 3. Imperative Shell Design

### 3.1 CLI Module (Entry Point)

```rust
// Imperative shell - handles all side effects
pub mod cli {
    use crate::core::*;
    
    pub struct CliArgs {
        pub input_files: Vec<PathBuf>,
        pub obfuscate: bool,
        pub force: bool,
        pub keep: bool,
        pub quiet: bool,
    }
    
    // Main application entry point
    pub fn run(args: CliArgs) -> Result<(), ApplicationError> {
        // 1. Validate inputs (with side effects)
        let validated_inputs = validate_inputs(&args.input_files)?;
        
        // 2. Check for duplicates (file I/O side effect)
        if !args.force {
            check_for_duplicates(&validated_inputs)?;
        }
        
        // 3. Get password (user interaction side effect)
        let password = prompt_for_password()?;
        
        // 4. Process each file
        for input_path in validated_inputs {
            process_single_file(&input_path, &password, &args)?;
        }
        
        Ok(())
    }
    
    fn process_single_file(
        input_path: &Path,
        password: &SecureString,
        args: &CliArgs,
    ) -> Result<(), ApplicationError> {
        // 1. Read file (I/O side effect)
        let content = fs::read(input_path)?;
        let filename = input_path.file_name()
            .ok_or(ApplicationError::InvalidFilename)?
            .to_string_lossy()
            .to_string();
        
        // 2. Create pure data structure
        let request = transform::create_encryption_request(
            content,
            filename,
            password.clone(),
            args.obfuscate,
        );
        
        // 3. Validate (pure function)
        validation::validate_encryption_request(&request)?;
        
        // 4. Encrypt (pure function)
        let encrypted = transform::encrypt_file(request)?;
        
        // 5. Write output (I/O side effect)
        let output_path = input_path.parent()
            .unwrap_or(Path::new("."))
            .join(&encrypted.suggested_filename);
        
        write_encrypted_file(&encrypted, &output_path, args.force)?;
        
        // 6. Remove source if requested (I/O side effect)
        if !args.keep {
            fs::remove_file(input_path)?;
        }
        
        // 7. Progress reporting (UI side effect)
        if !args.quiet {
            println!("Encrypted: {} -> {}", 
                input_path.display(), 
                encrypted.suggested_filename);
        }
        
        Ok(())
    }
}
```

### 3.2 File Operations Module

```rust
pub mod file_ops {
    use crate::core::*;
    
    // All functions here have side effects
    
    pub fn validate_inputs(paths: &[PathBuf]) -> Result<Vec<PathBuf>, FileError> {
        let mut validated = Vec::new();
        
        for path in paths {
            if !path.exists() {
                return Err(FileError::NotFound(path.clone()));
            }
            if !path.is_file() {
                return Err(FileError::NotAFile(path.clone()));
            }
            validated.push(path.clone());
        }
        
        Ok(validated)
    }
    
    pub fn check_for_duplicates(inputs: &[PathBuf]) -> Result<(), DuplicateError> {
        for input_path in inputs {
            let content = fs::read(input_path)?;
            let content_hash = crypto::hash_content(&content);
            
            // Scan target directory for existing .shadow files
            let target_dir = input_path.parent().unwrap_or(Path::new("."));
            let existing_hashes = scan_existing_shadow_files(target_dir)?;
            
            if validation::check_content_duplicate(&content_hash, &existing_hashes) {
                return Err(DuplicateError::ContentAlreadyEncrypted {
                    original_file: input_path.clone(),
                    content_hash,
                });
            }
        }
        
        Ok(())
    }
    
    fn scan_existing_shadow_files(dir: &Path) -> Result<Vec<[u8; 32]>, FileError> {
        let mut hashes = Vec::new();
        
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().map_or(false, |ext| ext == "shadow") {
                if let Ok(header) = read_shadow_file_header(&path) {
                    hashes.push(header.content_hash);
                }
            }
        }
        
        Ok(hashes)
    }
    
    fn read_shadow_file_header(path: &Path) -> Result<FileHeader, FileError> {
        let mut file = fs::File::open(path)?;
        let mut header_buffer = vec![0u8; 1024]; // Initial buffer size
        file.read_exact(&mut header_buffer[..8])?; // Read magic first
        
        // Validate magic and read full header
        if &header_buffer[..8] != b"SHADOW01" {
            return Err(FileError::InvalidFormat);
        }
        
        // Read rest of header based on format...
        // (Implementation details for header parsing)
        
        validation::validate_file_header(&header_buffer)
            .map_err(FileError::from)
    }
    
    pub fn write_encrypted_file(
        encrypted: &EncryptedFile,
        output_path: &Path,
        force: bool,
    ) -> Result<(), FileError> {
        if output_path.exists() && !force {
            return Err(FileError::OutputExists(output_path.to_path_buf()));
        }
        
        let serialized = transform::serialize_encrypted_file(encrypted)?;
        
        // Atomic write operation
        let temp_path = output_path.with_extension("shadow.tmp");
        fs::write(&temp_path, serialized)?;
        fs::rename(temp_path, output_path)?;
        
        Ok(())
    }
}
```

### 3.3 User Interface Module

```rust
pub mod ui {
    use std::io::{self, Write};
    
    pub fn prompt_for_password() -> Result<SecureString, UiError> {
        print!("Enter password: ");
        io::stdout().flush()?;
        
        // Use rpassword crate for secure password input
        let password1 = SecureString::new(rpassword::read_password()?);
        
        print!("Confirm password: ");
        io::stdout().flush()?;
        let password2 = SecureString::new(rpassword::read_password()?);
        
        if password1.as_str() != password2.as_str() {
            return Err(UiError::PasswordMismatch);
        }
        
        if password1.is_empty() {
            return Err(UiError::EmptyPassword);
        }
        
        Ok(password1)
    }
    
    pub fn display_progress(current: u64, total: u64) {
        if total > 10 * 1024 * 1024 { // Only for files > 10MB
            let percent = (current as f64 / total as f64) * 100.0;
            print!("\rProgress: {:.1}%", percent);
            io::stdout().flush().ok();
        }
    }
    
    pub fn display_error(error: &ApplicationError) {
        eprintln!("Error: {}", error);
        match error {
            ApplicationError::Duplicate(dup_err) => {
                eprintln!("Use --force to encrypt anyway");
            }
            ApplicationError::File(file_err) => {
                match file_err {
                    FileError::NotFound(path) => {
                        eprintln!("File not found: {}", path.display());
                    }
                    FileError::OutputExists(path) => {
                        eprintln!("Output file exists: {}", path.display());
                        eprintln!("Use --force to overwrite");
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}
```

---

## 4. Error Handling Strategy

### 4.1 Error Type Hierarchy

```rust
// Functional core errors - no side effects in creation/handling
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Key derivation failed")]
    KeyDerivation,
    #[error("Encryption failed")]
    Encryption,
    #[error("Invalid nonce size")]
    InvalidNonce,
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Empty password")]
    EmptyPassword,
    #[error("Empty file")]
    EmptyFile,
    #[error("Invalid header format")]
    InvalidHeader,
}

// Imperative shell errors - may involve side effects
#[derive(Debug, thiserror::Error)]
pub enum FileError {
    #[error("File not found: {0}")]
    NotFound(PathBuf),
    #[error("Not a file: {0}")]
    NotAFile(PathBuf),
    #[error("Output file exists: {0}")]
    OutputExists(PathBuf),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ApplicationError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),
    #[error("File error: {0}")]
    File(#[from] FileError),
    #[error("Duplicate content: {0}")]
    Duplicate(#[from] DuplicateError),
}
```

### 4.2 Error Propagation Pattern

```rust
// Functional core: Errors are values, no side effects
fn encrypt_content(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Pure error handling - no logging, no side effects
}

// Imperative shell: Handle errors with side effects
fn process_file(path: &Path) -> Result<(), ApplicationError> {
    match encrypt_file_content(path) {
        Ok(encrypted) => write_file(encrypted),
        Err(e) => {
            // Side effects: logging, user feedback
            log::error!("Failed to encrypt {}: {}", path.display(), e);
            ui::display_error(&e);
            Err(e)
        }
    }
}
```

---

## 5. Module Organization

### 5.1 Project Structure

```
src/
├── lib.rs              # Public API exports
├── bin/
│   └── shadow.rs       # Binary entry point (imperative shell)
├── core/               # Functional core
│   ├── mod.rs
│   ├── types.rs        # Pure data types (including SecureString)
│   ├── crypto.rs       # Pure crypto functions
│   ├── validation.rs   # Pure validation
│   └── transform.rs    # Pure transformations
├── shell/              # Imperative shell
│   ├── mod.rs
│   ├── cli.rs          # Command line interface
│   ├── file_ops.rs     # File operations
│   ├── ui.rs           # User interaction
│   └── errors.rs       # Error handling
└── testing/            # Test utilities
    ├── mod.rs
    ├── fixtures.rs     # Test data
    └── helpers.rs      # Test helpers
```

### 5.2 Dependency Boundaries

```rust
// lib.rs - Clean API boundary
pub mod core {
    // Only pure functions and types
    pub use crate::internal_core::*;
}

pub mod shell {
    // Side-effect functions
    pub use crate::internal_shell::*;
}

// Dependencies flow one way: shell -> core (never core -> shell)
```

---

## 6. Testing Strategy

### 6.1 Functional Core Testing

```rust
#[cfg(test)]
mod core_tests {
    use super::*;
    
    // Pure functions are easy to test
    #[test]
    fn test_encrypt_content() {
        let plaintext = b"test content";
        let key = SecureKey::new([0u8; 32]);
        let nonce = [0u8; 24];
        let aad = b"header";
        
        let result = crypto::encrypt_content(plaintext, &key, &nonce, aad);
        assert!(result.is_ok());
        
        // Deterministic with same inputs
        let key2 = SecureKey::new([0u8; 32]);
        let result2 = crypto::encrypt_content(plaintext, &key2, &nonce, aad);
        assert_eq!(result.unwrap(), result2.unwrap());
        // Both keys are automatically zeroized when they go out of scope
    }
    
    #[test]
    fn test_validation_pure() {
        let valid_request = EncryptionRequest {
            content: vec![1, 2, 3],
            metadata: FileMetadata {
                original_name: "test.txt".to_string(),
                content_hash: [0u8; 32],
                size: 3,
            },
            password: SecureString::new("password".to_string()),
            obfuscate_filename: false,
        };
        
        assert!(validation::validate_encryption_request(&valid_request).is_ok());
    }
    
    // Property-based testing with proptest
    use proptest::prelude::*;
    
    proptest! {
        #[test]
        fn test_content_hash_deterministic(content in prop::collection::vec(any::<u8>(), 0..1000)) {
            let hash1 = crypto::hash_content(&content);
            let hash2 = crypto::hash_content(&content);
            prop_assert_eq!(hash1, hash2);
        }
    }
}
```

### 6.2 Imperative Shell Testing

```rust
#[cfg(test)]
mod shell_tests {
    use super::*;
    use tempfile::TempDir;
    
    // Integration tests with temporary files
    #[test]
    fn test_file_processing() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, b"test content").unwrap();
        
        let args = CliArgs {
            input_files: vec![test_file.clone()],
            obfuscate: false,
            force: false,
            keep: true,
            quiet: true,
        };
        
        // This tests the full pipeline including I/O
        let result = process_single_file(&test_file, &SecureString::new("password".to_string()), &args);
        assert!(result.is_ok());
        
        // Verify output file exists
        let output_file = test_file.with_extension("txt.shadow");
        assert!(output_file.exists());
    }
    
    // Mock testing for external dependencies
    #[test]
    fn test_duplicate_detection() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create a file and encrypt it
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, b"unique content").unwrap();
        
        // First encryption should succeed
        let result1 = check_for_duplicates(&[test_file.clone()]);
        assert!(result1.is_ok());
        
        // Create the encrypted file
        // ... encryption logic ...
        
        // Second attempt should detect duplicate
        let result2 = check_for_duplicates(&[test_file]);
        assert!(result2.is_err());
    }
}
```

---

## 7. Implementation Phases

### 7.1 Phase 1: Functional Core (Week 1-2)

**Goal**: Implement all pure functions with comprehensive testing

**Tasks**:
1. Define core types (`types.rs`)
2. Implement cryptographic functions (`crypto.rs`)
3. Implement validation functions (`validation.rs`)
4. Implement transformation pipeline (`transform.rs`)
5. Write comprehensive unit tests
6. Property-based testing for crypto functions

**Deliverables**:
- Fully tested functional core
- 100% test coverage for pure functions
- Documentation for all public APIs

### 7.2 Phase 2: Imperative Shell (Week 3)

**Goal**: Implement side-effect functions and CLI

**Tasks**:
1. CLI argument parsing (`cli.rs`)
2. File operations (`file_ops.rs`)
3. User interface (`ui.rs`)
4. Error handling integration (`errors.rs`)
5. Integration testing

**Deliverables**:
- Working CLI application
- File I/O operations
- User interaction components

### 7.3 Phase 3: Integration & Polish (Week 4)

**Goal**: Complete application with quality features

**Tasks**:
1. Performance optimization
2. Progress reporting
3. Comprehensive error messages
4. Security audit of implementation
5. End-to-end testing
6. Documentation

**Deliverables**:
- Production-ready binary
- Complete test suite
- Security validation
- User documentation

---

## 8. Dependencies

### 8.1 Cryptographic Dependencies

```toml
[dependencies]
# Core cryptography
chacha20poly1305 = "0.10"     # XChaCha20-Poly1305
argon2 = "0.5"                # Key derivation
sha2 = "0.10"                 # Content hashing
rand = "0.9"                  # Random generation
hkdf = "0.12"                 # Key derivation for filenames
getrandom = "0.3"             # Secure random number generation
zeroize = "1.6"               # Secure memory zeroization
subtle = "2.5"                # Constant-time cryptographic operations

# UUID generation
uuid = { version = "1.10", features = ["v4", "rng"] }  # UUIDv4 for filename obfuscation

# Utility
clap = { version = "4", features = ["derive"] }
thiserror = "2.0"
rpassword = "7.2"             # Secure password input
tempfile = "3"                # Testing
```

### 8.2 Development Dependencies

```toml
[dev-dependencies]
criterion = "0.5"              # Benchmarking
tempfile = "3.8"               # Test utilities
proptest = "1.0"               # Property-based testing
hex = "0.4"                    # Test vectors
serde_json = "1.0"             # For test data serialization
```

---

## 9. Security Considerations

### 9.1 Memory Safety
- **SecureString wrapper**: Custom type encapsulates `zeroize` dependency for passwords
- **SecureKey wrapper**: Custom type for cryptographic keys (master keys, derived keys)
- **SecureBytes wrapper**: For sensitive intermediate data when needed
- **Automatic cleanup**: All secure types zeroize memory when dropped
- **Constant-time comparisons**: Use `subtle` crate for timing-safe operations

### 9.2 What Should Be Zeroized
- **Passwords**: Always use `SecureString` for user passwords
- **Cryptographic keys**: Use `SecureKey` for master keys and derived keys
- **Intermediate sensitive data**: Use `SecureBytes` for temporary sensitive data
- **What NOT to zeroize**: Public data like nonces, salts, ciphertext, headers

### 9.3 Error Security
- **No sensitive data in errors**: Never expose keys/passwords in error messages
- **Consistent error timing**: Prevent information leakage through error timing
- **Secure error propagation**: Errors don't carry sensitive data

### 9.4 Side-Channel Mitigation
- **Constant-time crypto**: Use timing-safe cryptographic implementations
- **Memory protection**: Clear sensitive data after use with secure types
- **Error uniformity**: Consistent behavior regardless of internal state

---

## 10. Success Criteria

### 10.1 Functional Requirements
- ✅ Encrypts files according to specification
- ✅ Supports both filename preservation and obfuscation
- ✅ Detects and prevents duplicate encryption
- ✅ Proper error handling and user feedback
- ✅ Secure password handling

### 10.2 Quality Requirements
- ✅ 100% test coverage for functional core
- ✅ Comprehensive integration tests
- ✅ Performance meets specification (50 MB/s)
- ✅ Memory usage within limits (2 GiB)
- ✅ Security audit passed

### 10.3 Architecture Requirements
- ✅ Clear separation between functional core and imperative shell
- ✅ Pure functions are side-effect free
- ✅ Testable components with good coverage
- ✅ Maintainable code structure
- ✅ Proper error handling patterns

---

**This implementation strategy provides a clear roadmap for building Shadow with the Functional Core, Imperative Shell pattern, ensuring security, maintainability, and testability.**