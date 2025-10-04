# Domain Layer Architecture Specification

This document specifies the domain layer architecture for the Shadow rewrite, building on preserved patterns and implementing missing features.

## 🏗️ **Domain Layer Overview**

The domain layer implements the core business logic using clean architecture principles:

```
┌─────────────────────────────────────────────────────────────┐
│                     CLI Layer (Binaries)                    │
├─────────────────────────────────────────────────────────────┤
│                  Application Services Layer                  │
├─────────────────────────────────────────────────────────────┤
│                     Domain Layer (Core)                     │
├─────────────────────────────────────────────────────────────┤
│                 Infrastructure Layer (I/O)                  │
└─────────────────────────────────────────────────────────────┘
```

## 🎯 **Domain Entities**

### 1. **EncryptedFile**
**Purpose**: Represents a complete encrypted file with header and content

```rust
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    header: HeaderV1, // Using new V1 format (was legacy V3)
    ciphertext: Vec<u8>,
    metadata: FileMetadata,
}

impl EncryptedFile {
    pub fn new(header: HeaderV1, ciphertext: Vec<u8>) -> Self;
    pub fn from_file(path: &Path, password: &str) -> Result<Self, CryptoError>;
    pub fn write_to_file(&self, path: &Path) -> Result<(), CryptoError>;
    
    // Metadata access
    pub fn original_filename(&self) -> Option<&str>;
    pub fn content_hash(&self) -> Option<&[u8; 32]>;
    pub fn algorithm(&self) -> AlgorithmId;
    pub fn version(&self) -> u16; // Will return 1 for new baseline
    
    // Validation
    pub fn validate_integrity(&self, password: &str) -> Result<(), CryptoError>;
    pub fn is_obfuscated(&self) -> bool;
}
```

### 2. **PlaintextFile**
**Purpose**: Represents a plaintext file ready for encryption

```rust
#[derive(Debug)]
pub struct PlaintextFile {
    path: PathBuf,
    content: Vec<u8>,
    metadata: FileMetadata,
    content_hash: [u8; 32],
}

impl PlaintextFile {
    pub fn from_path(path: &Path) -> Result<Self, CryptoError>;
    pub fn content_hash(&self) -> &[u8; 32];
    pub fn size(&self) -> usize;
    pub fn original_path(&self) -> &Path;
    pub fn metadata(&self) -> &FileMetadata;
}
```

### 3. **CryptoSession**
**Purpose**: Manages cryptographic state and key material for operations

```rust
#[derive(Debug)]
pub struct CryptoSession {
    config: Box<dyn CryptoConfig>,
    key_material: KeyMaterial,
    algorithm: AlgorithmId,
}

impl CryptoSession {
    pub fn new<T: CryptoConfig + 'static>(
        config: T, 
        password: &str, 
        salt: &[u8]
    ) -> Result<Self, CryptoError>;
    
    pub fn encrypt(&self, plaintext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CryptoError>;
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CryptoError>;
    pub fn algorithm(&self) -> AlgorithmId;
}

impl Drop for CryptoSession {
    fn drop(&mut self) {
        // Automatic key material zeroization
    }
}
```

### 4. **DuplicateDetector**
**Purpose**: Manages content fingerprinting and duplicate detection

```rust
#[derive(Debug)]
pub struct DuplicateDetector {
    content_database: ContentHashDatabase,
    search_paths: Vec<PathBuf>,
}

impl DuplicateDetector {
    pub fn new(search_paths: Vec<PathBuf>) -> Self;
    pub fn scan_existing_files(&mut self) -> Result<(), CryptoError>;
    pub fn check_duplicate(&self, content_hash: &[u8; 32]) -> Option<Vec<PathBuf>>;
    pub fn add_encrypted_file(&mut self, path: PathBuf, hash: [u8; 32]);
}
```

### 5. **FileMetadata**
**Purpose**: Represents file system metadata and attributes

```rust
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub original_filename: String,
    pub file_size: u64,
    pub modified_time: SystemTime,
    pub created_time: Option<SystemTime>,
    pub file_type: FileType,
}

#[derive(Debug, Clone)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    Other,
}
```

## 🔧 **Domain Services**

### 1. **EncryptionService**
**Purpose**: Orchestrates file encryption with all features

```rust
pub struct EncryptionService {
    duplicate_detector: Option<DuplicateDetector>,
    progress_reporter: ProgressReporter,
}

impl EncryptionService {
    pub fn new() -> Self;
    pub fn with_duplicate_detection(mut self, search_paths: Vec<PathBuf>) -> Self;
    pub fn with_progress_reporting(mut self, enabled: bool) -> Self;
    
    pub fn encrypt_file(
        &mut self,
        input_path: &Path,
        output_path: &Path,
        config: &dyn CryptoConfig,
        password: &str,
        options: EncryptionOptions,
    ) -> Result<EncryptionResult, CryptoError>;
    
    pub fn encrypt_multiple_files(
        &mut self,
        file_pairs: Vec<(PathBuf, PathBuf)>,
        config: &dyn CryptoConfig,
        password: &str,
        options: EncryptionOptions,
    ) -> Result<BatchResult<EncryptionResult>, CryptoError>;
}

#[derive(Debug, Clone)]
pub struct EncryptionOptions {
    pub obfuscate_filename: bool,
    pub force_overwrite: bool,
    pub remove_source: bool,
    pub check_duplicates: bool,
}

#[derive(Debug)]
pub struct EncryptionResult {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub content_hash: [u8; 32],
    pub algorithm: AlgorithmId,
    pub duration: Duration,
}

#[derive(Debug)]
pub struct BatchResult<T> {
    pub successful: Vec<T>,
    pub failed: Vec<(PathBuf, CryptoError)>,
    pub total_duration: Duration,
}
```

### 2. **DecryptionService**
**Purpose**: Orchestrates file decryption with filename restoration

```rust
pub struct DecryptionService {
    progress_reporter: ProgressReporter,
}

impl DecryptionService {
    pub fn new() -> Self;
    pub fn with_progress_reporting(mut self, enabled: bool) -> Self;
    
    pub fn decrypt_file(
        &mut self,
        input_path: &Path,
        output_path: Option<&Path>, // None = auto-detect from header
        password: &str,
        options: DecryptionOptions,
    ) -> Result<DecryptionResult, CryptoError>;
    
    pub fn decrypt_multiple_files(
        &mut self,
        input_paths: Vec<PathBuf>,
        password: &str,
        options: DecryptionOptions,
    ) -> Result<BatchResult<DecryptionResult>, CryptoError>;
}

#[derive(Debug, Clone)]
pub struct DecryptionOptions {
    pub force_overwrite: bool,
    pub remove_source: bool,
    pub verify_integrity: bool,
}

#[derive(Debug)]
pub struct DecryptionResult {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub original_filename: Option<String>,
    pub algorithm: AlgorithmId,
    pub duration: Duration,
}
```

### 3. **ListingService**
**Purpose**: Manages directory scanning and file information display

```rust
pub struct ListingService {
    progress_reporter: ProgressReporter,
}

impl ListingService {
    pub fn new() -> Self;
    
    pub fn scan_directory(
        &self,
        directory: &Path,
        password: &str,
    ) -> Result<DirectoryListing, CryptoError>;
}

#[derive(Debug)]
pub struct DirectoryListing {
    pub directory: PathBuf,
    pub files: Vec<EncryptedFileInfo>,
    pub scan_duration: Duration,
}

#[derive(Debug)]
pub struct EncryptedFileInfo {
    pub path: PathBuf,
    pub original_filename: Option<String>, // None if password failed
    pub algorithm: AlgorithmId,
    pub version: u16,
    pub size: u64,
    pub modified: SystemTime,
    pub password_valid: bool,
}
```

### 4. **MigrationService**
**Purpose**: Handles version migrations and compatibility

```rust
pub struct MigrationService {
    compatibility_matrix: CompatibilityMatrix,
    progress_reporter: ProgressReporter,
}

impl MigrationService {
    pub fn new() -> Self;
    
    pub fn analyze_file(&self, path: &Path) -> Result<MigrationAnalysis, CryptoError>;
    pub fn plan_migration(&self, files: Vec<PathBuf>) -> Result<MigrationPlan, CryptoError>;
    
    pub fn migrate_file(
        &mut self,
        path: &Path,
        target_version: u16,
        password: &str,
    ) -> Result<MigrationResult, CryptoError>;
}

#[derive(Debug)]
pub struct MigrationAnalysis {
    pub current_version: u16,
    pub target_version: u16,
    pub migration_path: Vec<u16>,
    pub is_required: bool,
    pub is_possible: bool,
}
```

### **Repository Interfaces**

**Important**: The Shadow rewrite follows a **stateless design** - no configuration files or persistent state. All relevant data must be stored in encrypted files themselves.

### 1. **FileRepository**
**Purpose**: Abstracts file system operations (read-only for configuration)

```rust
pub trait FileRepository: Send + Sync {
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, CryptoError>;
    fn write_file(&self, path: &Path, content: &[u8]) -> Result<(), CryptoError>;
    fn write_file_atomic(&self, path: &Path, content: &[u8]) -> Result<(), CryptoError>;
    fn delete_file_secure(&self, path: &Path) -> Result<(), CryptoError>;
    fn file_exists(&self, path: &Path) -> bool;
    fn file_metadata(&self, path: &Path) -> Result<FileMetadata, CryptoError>;
}

pub struct StandardFileRepository;
impl FileRepository for StandardFileRepository { /* ... */ }

pub struct MockFileRepository { /* for testing */ }
impl FileRepository for MockFileRepository { /* ... */ }
```

### 2. **PasswordRepository**
**Purpose**: Handles password input and validation (no persistence)

```rust
pub trait PasswordRepository: Send + Sync {
    fn prompt_password(&self, prompt: &str) -> Result<String, CryptoError>;
    fn prompt_password_with_confirmation(&self, prompt: &str) -> Result<String, CryptoError>;
    fn validate_password_strength(&self, password: &str) -> PasswordStrength;
}

pub enum PasswordStrength {
    Weak { issues: Vec<String> },
    Moderate,
    Strong,
}
```

**Note**: No `ConfigRepository` or persistent configuration. All settings determined at runtime from CLI arguments and encrypted file headers.

## 🎛️ **Application Services**

### 1. **EncryptionWorkflow**
**Purpose**: Coordinates encryption with all features and validations (stateless)

```rust
pub struct EncryptionWorkflow {
    encryption_service: EncryptionService,
    file_repo: Box<dyn FileRepository>,
    password_repo: Box<dyn PasswordRepository>,
    // Note: No config repository - all configuration from CLI args
}

impl EncryptionWorkflow {
    pub fn execute(
        &mut self,
        input_patterns: Vec<String>,
        algorithm: AlgorithmId, // From CLI arguments
        options: EncryptionOptions,
    ) -> Result<WorkflowResult, CryptoError> {
        // 1. Expand glob patterns
        let file_paths = self.expand_patterns(input_patterns)?;
        
        // 2. Validate all files exist and are readable
        self.validate_input_files(&file_paths)?;
        
        // 3. Check for already encrypted files (double-encryption prevention)
        self.check_already_encrypted(&file_paths)?;
        
        // 4. Get password with confirmation (if encrypting)
        let password = self.password_repo.prompt_password_with_confirmation(
            "Enter password for encryption: "
        )?;
        
        // 5. Create configuration from CLI algorithm choice (no persistence)
        let config = self.create_config_for_algorithm(algorithm)?;
        
        // 6. Execute encryption
        let results = self.encryption_service.encrypt_multiple_files(
            file_paths, &*config, &password, options
        )?;
        
        Ok(WorkflowResult::Encryption(results))
    }
}
```

### 2. **DecryptionWorkflow**
**Purpose**: Coordinates decryption with filename restoration (stateless)

```rust
pub struct DecryptionWorkflow {
    decryption_service: DecryptionService,
    file_repo: Box<dyn FileRepository>,
    password_repo: Box<dyn PasswordRepository>,
}

impl DecryptionWorkflow {
    pub fn execute(
        &mut self,
        input_patterns: Vec<String>,
        options: DecryptionOptions,
    ) -> Result<WorkflowResult, CryptoError> {
        // 1. Expand patterns and validate files
        // 2. Get password (single prompt for decryption)
        // 3. Algorithm detection from file headers (no config needed)
        // 4. Execute decryption with filename restoration
        // 5. Return results
    }
}
```

## 📊 **Dependency Injection Container**

```rust
pub struct Container {
    file_repo: Box<dyn FileRepository>,
    password_repo: Box<dyn PasswordRepository>,
    // Note: No config repository - stateless design
}

impl Container {
    pub fn new() -> Self {
        Self {
            file_repo: Box::new(StandardFileRepository),
            password_repo: Box::new(StandardPasswordRepository),
        }
    }
    
    pub fn for_testing() -> Self {
        Self {
            file_repo: Box::new(MockFileRepository::new()),
            password_repo: Box::new(MockPasswordRepository::new()),
        }
    }
    
    pub fn encryption_workflow(&self, algorithm: AlgorithmId) -> EncryptionWorkflow { 
        // Pass algorithm directly - no config persistence
    }
    pub fn decryption_workflow(&self) -> DecryptionWorkflow { /* ... */ }
    pub fn listing_workflow(&self) -> ListingWorkflow { /* ... */ }
    pub fn migration_workflow(&self) -> MigrationWorkflow { /* ... */ }
}
```

## 🧪 **Testing Strategy**

### Unit Testing
- **Domain Entities**: Test all business rules and validations
- **Domain Services**: Test core algorithms and logic
- **Repository Interfaces**: Test with mock implementations

### Integration Testing
- **Application Services**: Test complete workflows
- **File Operations**: Test with real filesystem
- **Cryptographic Operations**: Test with real algorithms

### Property-Based Testing
- **Encryption/Decryption Roundtrips**: Ensure data integrity
- **Header Serialization**: Ensure deterministic and parseable output
- **Migration Compatibility**: Ensure version upgrades preserve data

## 🔒 **Security Considerations**

### Memory Safety
- All key material in `SecureBox` with automatic zeroization
- Passwords zeroized immediately after use
- No plaintext stored longer than necessary

### Error Handling
- No sensitive information in error messages
- Consistent error types across domain layer
- Actionable user guidance without implementation details

### Cryptographic Hygiene
- Crypto operations isolated in domain services
- Algorithm implementations swappable via configuration
- All random values from cryptographically secure sources