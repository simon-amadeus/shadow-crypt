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
    
    fn encrypt_with_key(data: &[u8], key: &SecureKey, nonce: &[u8; 24]) -> Result<Vec<u8>, CryptoError> {
        // XChaCha20-Poly1305 encryption implementation
        // Uses key.as_bytes() internally
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

## 5. Module Organization with Vertical Slicing

### 5.1 Crate-Based Vertical Slicing + Functional Core/Imperative Shell

Each feature is vertically sliced into separate crates with their own functional core and imperative shell, while sharing common foundational components through the `shadow-core` and `shadow-shell` crates.

### 5.2 Shared Foundation Components

#### shadow-core (Pure - No I/O)
```rust
// shadow-core/src/types.rs - Common types used by all features
pub struct SecureString(zeroize::Zeroizing<String>);
pub struct SecureKey(zeroize::Zeroizing<[u8; 32]>);
pub struct FileHeader { /* ... */ }
pub struct FilenameData { /* ... */ }

// shadow-core/src/crypto.rs - Pure crypto primitives
pub fn derive_key(password: &SecureString, salt: &[u8; 16]) -> Result<SecureKey, CryptoError>;
pub fn encrypt_content(plaintext: &[u8], key: &SecureKey, nonce: &[u8; 24], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
pub fn decrypt_content(ciphertext: &[u8], key: &SecureKey, nonce: &[u8; 24], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
pub fn hash_content(content: &[u8]) -> [u8; 32];

// shadow-core/src/file_format.rs - Pure file format handling
pub fn serialize_header(header: &FileHeader) -> Result<Vec<u8>, SerializationError>;
pub fn deserialize_header(data: &[u8]) -> Result<FileHeader, SerializationError>;
pub fn validate_file_header(header: &FileHeader) -> Result<(), ValidationError>;
```

#### shadow-shell (Impure - I/O Utilities)
```rust
// shadow-shell/src/file_ops.rs - Common file operations
pub fn read_file_safely(path: &Path) -> Result<Vec<u8>, FileError>;
pub fn write_file_atomically(path: &Path, data: &[u8]) -> Result<(), FileError>;
pub fn scan_shadow_files(dir: &Path) -> Result<Vec<PathBuf>, FileError>;

// shadow-shell/src/cli_helpers.rs - CLI utilities
pub fn parse_glob_patterns(patterns: &[String]) -> Result<Vec<PathBuf>, GlobError>;
pub fn prompt_for_password() -> Result<SecureString, UiError>;
pub fn confirm_overwrite(path: &Path) -> Result<bool, UiError>;

// shadow-shell/src/ui.rs - User interface utilities
pub fn display_progress(current: u64, total: u64, file: &str);
pub fn display_error(error: &dyn Error);
pub fn display_success(message: &str);
```

### 5.3 Feature-Specific Components

#### Encryption Feature
```rust
// encryption/core/types.rs - Encryption-specific types
pub struct EncryptionRequest {
    pub content: Vec<u8>,
    pub metadata: FileMetadata,
    pub password: SecureString,
    pub obfuscate_filename: bool,
}

pub struct EncryptedFile {
    pub header: FileHeader,
    pub ciphertext: Vec<u8>,
    pub suggested_filename: String,
}

// encryption/core/pipeline.rs - Pure encryption pipeline
pub fn encrypt_file(request: EncryptionRequest) -> Result<EncryptedFile, EncryptionError>;
pub fn create_encryption_request(/* ... */) -> EncryptionRequest;

// encryption/shell/cli.rs - Encryption CLI
pub fn run_encryption(args: EncryptionArgs) -> Result<(), ApplicationError>;
```

#### Decryption Feature  
```rust
// decryption/core/types.rs - Decryption-specific types
pub struct DecryptionRequest {
    pub encrypted_file: Vec<u8>,
    pub password: SecureString,
    pub output_path: Option<PathBuf>,
}

pub struct DecryptedFile {
    pub content: Vec<u8>,
    pub original_filename: String,
    pub metadata: FileMetadata,
}

// decryption/core/pipeline.rs - Pure decryption pipeline
pub fn decrypt_file(request: DecryptionRequest) -> Result<DecryptedFile, DecryptionError>;

// decryption/shell/cli.rs - Decryption CLI
pub fn run_decryption(args: DecryptionArgs) -> Result<(), ApplicationError>;
```

#### Listing Feature
```rust
// listing/core/types.rs - Listing-specific types
pub struct FileInfo {
    pub path: PathBuf,
    pub header: FileHeader,
    pub size: u64,
    pub created: SystemTime,
}

pub struct ListingOptions {
    pub show_hashes: bool,
    pub show_metadata: bool,
    pub format: OutputFormat,
}

// listing/core/analysis.rs - Pure file analysis
pub fn analyze_shadow_file(path: &Path) -> Result<FileInfo, AnalysisError>;
pub fn extract_file_info(encrypted_data: &[u8]) -> Result<FileInfo, AnalysisError>;

// listing/shell/cli.rs - Listing CLI
pub fn run_listing(args: ListingArgs) -> Result<(), ApplicationError>;
```

### 5.4 Crate-Based Architecture with Clear Core/Shell Separation

#### Workspace Structure

```toml
# Cargo.toml - Workspace definition
[workspace]
members = [
    "crates/shadow-core",           # Pure shared foundation (crypto, types, validation)
    "crates/shadow-shell",          # Shared I/O utilities (file ops, CLI helpers)
    "crates/shadow-encryption-core", 
    "crates/shadow-encryption-shell",
    "crates/shadow-decryption-core",
    "crates/shadow-decryption-shell", 
    "crates/shadow-listing-core",
    "crates/shadow-listing-shell",
    "crates/shadow-cli"
]

# crates/shadow-core/Cargo.toml - Pure foundation, no I/O
[package]
name = "shadow-core"
version = "0.1.0"

[dependencies]
zeroize = "1.6"
chacha20poly1305 = "0.10"
argon2 = "0.5"
sha2 = "0.10"
uuid = { version = "1.10", features = ["v4", "rng"] }
# ONLY pure dependencies - no file I/O, no CLI

# crates/shadow-shell/Cargo.toml - Shared I/O utilities
[package]
name = "shadow-shell"
version = "0.1.0"

[dependencies]
shadow-core = { path = "../shadow-core" }
clap = "4"
rpassword = "7.2"
tempfile = "3"
colored = "3.0"
# I/O and CLI utilities that all shells can use

# crates/shadow-encryption-core/Cargo.toml  
[package]
name = "shadow-encryption-core"
version = "0.1.0"

[dependencies]
shadow-core = { path = "../shadow-core" }
# ONLY pure dependencies - cannot import shell utilities

# crates/shadow-encryption-shell/Cargo.toml
[package] 
name = "shadow-encryption-shell"
version = "0.1.0"

[dependencies]
shadow-core = { path = "../shadow-core" }
shadow-shell = { path = "../shadow-shell" }
shadow-encryption-core = { path = "../shadow-encryption-core" }
# Can use both core logic and shell utilities
```

#### Directory Structure with Clear Core/Shell Distinction

```
shadow/
├── Cargo.toml (workspace)
├── crates/
│   ├── shadow-core/              # PURE: Shared foundation (no I/O)
│   │   ├── Cargo.toml           # crypto deps only
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── types.rs          # SecureString, SecureKey, FileHeader
│   │       ├── crypto.rs         # Pure crypto functions
│   │       ├── file_format.rs    # Serialization (pure functions)
│   │       ├── validation.rs     # Pure validation functions
│   │       └── errors.rs         # Core error types
│   ├── shadow-shell/             # IMPURE: Shared I/O utilities
│   │   ├── Cargo.toml           # I/O and CLI deps
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── file_ops.rs       # Common file operations
│   │       ├── cli_helpers.rs    # CLI parsing utilities
│   │       ├── ui.rs             # Progress, colors, formatting
│   │       └── errors.rs         # I/O error handling
│   ├── shadow-encryption-core/   # PURE: Encryption business logic
│   │   ├── Cargo.toml           # depends: shadow-core only
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── types.rs          # EncryptionRequest, EncryptedFile
│   │       ├── pipeline.rs       # encrypt_file() - pure function
│   │       └── validation.rs     # Encryption-specific validation
│   ├── shadow-encryption-shell/  # IMPURE: Encryption I/O and CLI
│   │   ├── Cargo.toml           # depends: shadow-core + shadow-shell + shadow-encryption-core
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── cli.rs            # Encryption CLI
│   │       ├── file_ops.rs       # Encryption file operations
│   │       └── runner.rs         # Main encryption workflow
│   ├── shadow-decryption-core/   # PURE: Decryption business logic
│   ├── shadow-decryption-shell/  # IMPURE: Decryption I/O and CLI
│   ├── shadow-listing-core/      # PURE: Listing business logic
│   ├── shadow-listing-shell/     # IMPURE: Listing I/O and CLI
│   └── shadow-cli/              # IMPURE: Final binaries
│       ├── Cargo.toml           # depends: all shells only
│       └── src/
│           └── bin/
│               ├── shadow.rs     # uses shadow-encryption-shell
│               ├── unshadow.rs   # uses shadow-decryption-shell
│               └── shadows.rs    # uses shadow-listing-shell
```

### 5.5 Dependency Flow and Enforcement

```
┌─────────────────────────────────────────────────────────────┐
│                    Binary Layer                              │
│  shadow.rs    │   unshadow.rs   │   shadows.rs              │
└─────────────────┼─────────────────┼─────────────────────────┘
                  │                 │                          
┌─────────────────┼─────────────────┼─────────────────────────┐
│           Feature Shells (Imperative)                       │
│  encryption/    │  decryption/    │  listing/               │
│  shell/         │  shell/         │  shell/                 │
└─────────────────┼─────────────────┼─────────────────────────┘
                  │                 │                          
┌─────────────────┼─────────────────┼─────────────────────────┐
│           Feature Cores (Functional)                        │
│  encryption/    │  decryption/    │  listing/               │
│  core/          │  core/          │  core/                  │
└─────────────────┼─────────────────┼─────────────────────────┘
                  │                 │                          
┌─────────────────────────────────────────────────────────────┐
│      shadow-shell (Shared I/O utilities)                    │
│      file_ops, cli_helpers, ui, progress                    │
└─────────────────────────────────────────────────────────────┘
                  │                 │                          
┌─────────────────────────────────────────────────────────────┐
│      shadow-core (Pure shared foundation)                   │
│      types, crypto, file_format, validation                 │
└─────────────────────────────────────────────────────────────┘

Dependencies flow: Shell -> Core -> shadow-shell -> shadow-core
```

**Enforcement guarantees:**
- ✅ **shadow-core**: Cannot import any I/O dependencies (compile-time enforced)
- ✅ **shadow-shell**: Can only import shadow-core + I/O dependencies  
- ✅ **feature-cores**: Can only import shadow-core (compile-time enforced)
- ✅ **feature-shells**: Can import shadow-core + shadow-shell + their feature-core
- ✅ **binaries**: Can only import feature-shells (not cores directly)

### 5.6 Benefits of This Architecture

#### Vertical Slicing Benefits
- **Feature Independence**: Each feature can be developed, tested, and deployed independently
- **Team Scalability**: Different teams can work on different features without conflicts
- **Clear Ownership**: Each feature slice has clear boundaries and responsibilities
- **Reduced Coupling**: Features don't depend on each other's implementation details

#### Functional Core/Imperative Shell Benefits per Feature
- **Testability**: Each feature's core logic is pure and easily testable
- **Security**: Crypto operations isolated in pure functions per feature
- **Maintainability**: Clear separation between business logic and infrastructure per feature
- **Reusability**: Shared components can be reused across features

#### Combined Benefits
- **Scalable Architecture**: Easy to add new features (e.g., batch operations, file migration)
- **Consistent Patterns**: Each feature follows the same architectural pattern
- **Shared Security**: Common crypto primitives ensure consistent security across features
- **Independent Evolution**: Features can evolve independently while sharing stable foundations

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

## 7. Implementation Phases (Crate-Based Vertical Slicing)

### 7.1 Phase 1: Foundation Crates (Week 1)

**Goal**: Implement `shadow-core` and `shadow-shell` crates

**Tasks**:
1. **Setup Workspace** (`Cargo.toml`)
   - Define workspace with all planned crates
   - Set up dependency relationships
2. **Shadow Core** (`crates/shadow-core/`)
   - `SecureString`, `SecureKey`, `SecureBytes` types
   - Pure cryptographic functions (no I/O allowed)
   - File format serialization/deserialization (pure)
   - Common error types and validation
3. **Shadow Shell** (`crates/shadow-shell/`)
   - Common file operations utilities
   - CLI helper functions
   - UI utilities (progress, formatting, colors)
   - I/O error handling
4. **Comprehensive Testing**
   - 100% test coverage for shadow-core
   - Integration tests for shadow-shell
   - Property-based testing for crypto functions

**Deliverables**:
- Working `shadow-core` crate (pure, no I/O dependencies)
- Working `shadow-shell` crate (I/O utilities)
- Complete test suite for both foundation crates
- Published API documentation

### 7.2 Phase 2: Encryption Feature (Week 2)

**Goal**: Complete encryption feature as first vertical slice

**Tasks**:
1. **Encryption Core** (`crates/shadow-encryption-core/`)
   - Pure encryption pipeline
   - Encryption-specific types and validation
   - Duplicate detection logic
   - **Depends only on**: `shadow-core`
2. **Encryption Shell** (`crates/shadow-encryption-shell/`)
   - CLI argument parsing using shadow-shell utilities
   - File I/O operations using shadow-shell helpers
   - User interaction and progress reporting
   - **Depends on**: `shadow-core` + `shadow-shell` + `shadow-encryption-core`
3. **Integration Testing**
   - End-to-end encryption workflow tests
   - Error handling validation

**Deliverables**:
- Working `shadow` binary
- Complete encryption feature
- Integration test suite

### 7.3 Phase 3: Decryption Crates (Week 3)

**Goal**: Add decryption feature as new crate pair

**Tasks**:
1. **Decryption Core** (`crates/shadow-decryption-core/`)
   - Pure decryption pipeline
   - Password verification and file integrity validation
   - **Depends only on**: `shadow-core`
2. **Decryption Shell** (`crates/shadow-decryption-shell/`)
   - CLI for decryption operations using shadow-shell utilities
   - Output file handling and error reporting
   - **Depends on**: `shadow-core` + `shadow-shell` + `shadow-decryption-core`
3. **Update CLI Binary** (`crates/shadow-cli/src/bin/unshadow.rs`)
   - Add unshadow binary using decryption shell

**Deliverables**:
- Working `unshadow` binary
- Complete decryption feature across two crates
- Round-trip encryption/decryption validation

### 7.4 Phase 4: Listing Crates (Week 4)

**Goal**: Add file analysis feature as third crate pair

**Tasks**:
1. **Listing Core** (`crates/shadow-listing-core/`)
   - Pure file analysis functions
   - Metadata extraction and output formatting  
   - **Depends only on**: `shadow-core`
2. **Listing Shell** (`crates/shadow-listing-shell/`)
   - CLI for listing operations using shadow-shell utilities
   - Directory scanning and pretty-printed output
   - **Depends on**: `shadow-core` + `shadow-shell` + `shadow-listing-core`
3. **Final Polish**
   - Complete `shadows` binary
   - Performance optimization across all crates
   - Security audit and documentation

**Deliverables**:
- Working `shadows` binary
- Complete listing feature across two crates
- Production-ready multi-crate system

### 7.5 Future Feature Addition Pattern

**Adding a new feature** (e.g., `shadowmigrate` for format migration):

1. **Create Feature Crates**:
   ```
   crates/shadow-migration-core/     # Pure migration logic
   ├── Cargo.toml                   # depends: shadow-core only
   └── src/
       ├── lib.rs
       ├── types.rs                 # Migration-specific types
       ├── pipeline.rs              # Pure migration logic
       └── validation.rs            # Migration validation

   crates/shadow-migration-shell/   # Migration I/O and CLI
   ├── Cargo.toml                  # depends: shadow-core + shadow-shell + shadow-migration-core
   └── src/
       ├── lib.rs
       ├── cli.rs                  # CLI handling
       ├── file_ops.rs             # File operations
       └── runner.rs               # Main migration workflow
   ```

2. **Add Binary**:
   ```toml
   # crates/shadow-cli/Cargo.toml
   [[bin]]
   name = "shadowmigrate"
   path = "src/bin/shadowmigrate.rs"
   
   [dependencies]
   shadow-migration-shell = { path = "../shadow-migration-shell" }
   # ... other shells
   ```

3. **Implement Using Shared Foundation**:
   - Reuse `shadow-core` for cryptographic operations
   - Reuse `shadow-shell` for file I/O and CLI utilities
   - Follow same FC/IS pattern as other features

4. **Independent Development**:
   - No changes needed to existing crates
   - Self-contained testing and validation
   - Clear crate boundaries and compile-time dependency enforcement

This pattern ensures **linear scalability** as features are added.

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