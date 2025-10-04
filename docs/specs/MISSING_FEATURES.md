# Missing Features Implementation Specification

This document specifies the features that are documented in the feature requirements but not implemented in the current codebase. These must be implemented in the rewrite.

## 🚨 **Critical Missing Features**

### 1. **Double Password Verification**
**Status**: ❌ **NOT IMPLEMENTED** (Documented as ✅)

**Current State**: Only single password prompt exists
**Required Implementation**:

```rust
// First, extend CryptoError with new variants needed for missing features
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    // ... existing variants ...
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Duplicate content detected")]
    DuplicateContentDetected { 
        existing_files: Vec<PathBuf>, 
        suggestion: String 
    },
}

pub fn prompt_password_with_confirmation(prompt: &str) -> Result<String, CryptoError> {
    let password1 = rpassword::prompt_password(prompt)?;
    let password2 = rpassword::prompt_password("Confirm password: ")?;
    
    if password1 != password2 {
        return Err(CryptoError::ValidationError(
            "Passwords do not match. Please try again.".to_string()
        ));
    }
    
    if password1.is_empty() {
        return Err(CryptoError::ValidationError(
            "Password cannot be empty".to_string()
        ));
    }
    
    Ok(password1)
}
```

**Integration Points**:
- Encryption operations in `shadow` binary
- Password change operations (if implemented)
- Initial key setup operations

### 2. **Duplicate Content Detection**
**Status**: ❌ **NOT IMPLEMENTED** (Documented as ✅)

**Current State**: V3 header has `ContentHash` TLV field but no detection logic
**Required Implementation**:

```rust
pub struct ContentHashDatabase {
    hash_to_files: HashMap<[u8; 32], Vec<PathBuf>>,
}

impl ContentHashDatabase {
    pub fn scan_directory(&mut self, dir: &Path) -> Result<(), CryptoError> {
        // Scan for existing .shadow files and build hash index
    }
    
    pub fn check_duplicate_content(&self, content_hash: &[u8; 32]) -> Option<&[PathBuf]> {
        self.hash_to_files.get(content_hash)
    }
    
    pub fn add_encrypted_file(&mut self, file_path: PathBuf, content_hash: [u8; 32]) {
        self.hash_to_files.entry(content_hash)
            .or_insert_with(Vec::new)
            .push(file_path);
    }
}

pub fn check_for_duplicate_content(
    input_path: &Path,
    search_directories: &[PathBuf]
) -> Result<Option<Vec<PathBuf>>, CryptoError> {
    // 1. Calculate SHA-256 hash of input file content
    let content_hash = calculate_file_hash(input_path)?;
    
    // 2. Scan directories for existing .shadow files
    let mut database = ContentHashDatabase::new();
    for dir in search_directories {
        database.scan_directory(dir)?;
    }
    
    // 3. Check if hash already exists
    Ok(database.check_duplicate_content(&content_hash).map(|files| files.clone()))
}
```

**Integration Points**:
- Pre-encryption validation in `shadow` binary
- Progress reporting: "🔍 Checking for duplicate content..."
- User prompts for handling duplicates

**User Experience**:
```
🔐 Encrypting file: document_copy.txt
🔍 Checking for duplicate content... ⚠️ (3ms)
❌ Error: File content matches already encrypted file 'document.txt.shadow'
   Duplicate encryption prevented to avoid redundant encrypted files.
   Hint: Use different content or decrypt existing file first.
```

### 3. **--keep Flag Implementation**
**Status**: ❌ **NOT IMPLEMENTED** (Documented as ✅)

**Current State**: Only `--remove-source` flag exists, behavior is opposite of documented
**Required Implementation**:

Update CLI argument parsing in all binaries:

```rust
// Current: remove_source defaults to false, --remove-source sets to true
// Required: remove_source defaults to true, --keep sets to false

fn parse_args(args: &[String]) -> (..., bool, ...) {
    let mut remove_source = true; // Default: remove source files
    
    // Parse arguments
    match args[i].as_str() {
        "--keep" | "-k" => {
            remove_source = false; // Keep source files
            i += 1;
        }
        // ... other arguments
    }
    
    (/*...*/, remove_source, /*...*/)
}
```

**Required CLI Updates**:
- `shadow`: Add `--keep`/`-k` flag, default to removing source
- `unshadow`: Add `--keep`/`-k` flag, default to removing source  
- Update help text to reflect correct default behavior
- Update examples in documentation

### 4. **Source Removal Default Behavior**
**Status**: ❌ **INCORRECT DEFAULT** (Documented behavior opposite of implementation)

**Current State**: Source files preserved by default
**Required Implementation**: Source files removed by default

**Behavior Changes Required**:
```rust
// All encryption/decryption operations should default to:
let remove_source = true; // Remove source files by default

// Only preserve when explicitly requested:
if args.contains("--keep") || args.contains("-k") {
    remove_source = false;
}
```

**User Experience Impact**:
```bash
# Default behavior (should remove source):
shadow secret.txt                    # secret.txt deleted after encryption
unshadow secret.txt.shadow          # secret.txt.shadow deleted after decryption

# Explicit preservation:
shadow --keep secret.txt             # secret.txt preserved
unshadow --keep secret.txt.shadow    # secret.txt.shadow preserved
```

## 🔧 **Enhancement Features**

### 5. **Content Fingerprinting for Duplicate Detection**
**Status**: 🆕 **NEW FEATURE** (Infrastructure exists in V3 TLV)

**Implementation Strategy**:
```rust
pub fn calculate_content_fingerprint(file_path: &Path) -> Result<[u8; 32], CryptoError> {
    use sha2::{Sha256, Digest};
    
    let mut file = File::open(file_path)?;
    let mut hasher = Sha256::new();
    
    // Stream file content through hasher to handle large files
    let mut buffer = [0u8; 64 * 1024]; // 64KB buffer
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 { break; }
        hasher.update(&buffer[..bytes_read]);
    }
    
    Ok(hasher.finalize().into())
}

pub fn store_content_hash_in_header(
    header: &mut HeaderV3,
    content_hash: [u8; 32]
) {
    header.add_tlv_field(TlvFieldType::ContentHash, content_hash.to_vec());
}

pub fn extract_content_hash_from_header(
    header: &HeaderV3
) -> Option<[u8; 32]> {
    header.get_tlv_field(TlvFieldType::ContentHash)
        .and_then(|data| {
            if data.len() == 32 {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(data);
                Some(hash)
            } else {
                None
            }
        })
}
```

### 6. **Improved Progress Reporting for Duplicate Detection**
**Status**: 🆕 **NEW FEATURE**

**Integration with existing progress system**:
```rust
pub fn encrypt_with_duplicate_check(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    show_progress: bool
) -> Result<(), CryptoError> {
    if show_progress {
        print!("🔍 Checking for duplicate content...");
        std::io::stdout().flush().ok();
    }
    
    let start_time = Instant::now();
    
    // Check for duplicates
    let search_dirs = vec![
        input_path.parent().unwrap_or(Path::new(".")).to_path_buf(),
        // Add other search directories
    ];
    
    match check_for_duplicate_content(input_path, &search_dirs)? {
        Some(duplicate_files) => {
            if show_progress {
                let duration = start_time.elapsed();
                println!(" ⚠️ ({})", format_duration(duration));
            }
            
            return Err(CryptoError::DuplicateContentDetected {
                existing_files: duplicate_files,
                suggestion: "Use different content or decrypt existing file first.".to_string(),
            });
        }
        None => {
            if show_progress {
                let duration = start_time.elapsed();
                println!(" ✓ ({})", format_duration(duration));
            }
        }
    }
    
    // Proceed with normal encryption...
}
```

## 📋 **Implementation Priority**

### High Priority (Core Functionality)
1. **Double Password Verification** - Critical for preventing data loss
2. **--keep Flag Implementation** - Essential CLI consistency
3. **Source Removal Default Behavior** - Align implementation with documentation

### Medium Priority (Enhanced Security)
4. **Duplicate Content Detection** - Prevents redundant encrypted files
5. **Content Fingerprinting** - Infrastructure for duplicate detection

### Low Priority (Polish)
6. **Enhanced Progress Reporting** - Better user experience during duplicate checks

## 🧪 **Testing Requirements**

### Unit Tests Required
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_double_password_verification_success() {
        // Test matching passwords
    }
    
    #[test]
    fn test_double_password_verification_mismatch() {
        // Test password mismatch error
    }
    
    #[test]
    fn test_duplicate_content_detection() {
        // Test duplicate file detection
    }
    
    #[test]
    fn test_keep_flag_behavior() {
        // Test --keep flag preserves source files
    }
    
    #[test]
    fn test_default_source_removal() {
        // Test default behavior removes source files
    }
}
```

### Integration Tests Required
```rust
#[test]
fn test_cli_keep_flag_integration() {
    // Test end-to-end CLI behavior with --keep flag
}

#[test]
fn test_duplicate_detection_integration() {
    // Test duplicate detection in real file scenarios
}

#[test]
fn test_double_password_cli_integration() {
    // Test password confirmation in CLI environment
}
```

## 🔒 **Security Considerations**

### Password Handling
- Passwords must be zeroized immediately after use
- No password storage in memory longer than necessary
- Secure comparison for password verification

### Content Hashing
- Use cryptographically secure hash function (SHA-256)
- Hash calculation must handle large files efficiently
- Content hashes stored in encrypted TLV fields

### Error Messages
- Don't leak sensitive information in duplicate detection errors
- Provide actionable guidance without revealing file contents
- Maintain consistent error handling patterns