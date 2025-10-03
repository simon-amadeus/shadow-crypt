//! Shadow - High-security file encryption library
//! 
//! Shadow is a comprehensive file encryption system providing military-grade security
//! with an intuitive command-line interface. It implements authenticated encryption,
//! secure key derivation, and optional filename obfuscation for complete file protection.
//! 
//! # Features
//! 
//! - **AES-256-GCM** and **XChaCha20-Poly1305** authenticated encryption
//! - **Argon2id** key derivation with adaptive parameters
//! - **Reversible filename obfuscation** with collision resistance
//! - **Secure memory handling** with automatic zeroization
//! - **Vertical slicing architecture** with separate binaries for each use case
//! - **Version-aware format** supporting future algorithm upgrades
//! 
//! # Binaries
//! 
//! Shadow provides specialized binaries for different use cases:
//! 
//! - **`shadow`** - Encrypt files and directories
//! - **`unshadow`** - Decrypt files and restore original names
//! - **`shadows`** - List encrypted files without decryption
//! - **`shadowview`** - Securely view encrypted files temporarily
//! - **`shadowedit`** - Edit encrypted files in-place with atomic updates
//! - **`shadowmigrate`** - Migrate between encryption format versions
//! - **`shadowbench`** - Performance benchmarking and validation
//! 
//! # Architecture
//! 
//! The codebase follows a vertical slicing architecture where each binary has its own
//! module containing all necessary functionality. This design ensures:
//! 
//! - **Clear separation of concerns** between different use cases
//! - **Minimal coupling** between modules while maintaining clean interfaces
//! - **Easy extensibility** for new features and algorithms
//! - **Comprehensive testing** with focused test suites per module
//! 
//! ## Module Organization
//! 
//! Each use case module follows a standard pattern:
//! - `mod.rs` - Public API, documentation, and re-exports
//! - Core implementation files (e.g., `encrypt_file.rs`, `decrypt_file.rs`)
//! - `cli.rs` - Command-line interface and argument parsing
//! - Utility modules as needed (e.g., `filename_obfuscation.rs`)
//! 
//! ## Shared Infrastructure
//! 
//! Common cryptographic primitives and utilities are provided through the `shared`
//! module, which includes:
//! - **Core cryptographic operations** (AES-GCM, XChaCha20-Poly1305, Argon2)
//! - **File format handling** with versioned headers
//! - **Error handling** and recovery mechanisms
//! - **Performance monitoring** and progress reporting
//! 
//! # Quick Start
//! 
//! ```rust,no_run
//! use shadow_crypt::encryption::encrypt_single_file_with_config;
//! use shadow_crypt::decryption::decrypt_single_file_with_config;
//! use shadow_crypt::shared::algorithms::aes_gcm_config::AesGcmConfig;
//! use shadow_crypt::shared::algorithms::config::CryptoConfig;
//! use std::path::Path;
//! 
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Encrypt a file
//! let input = Path::new("document.txt");
//! let encrypted = Path::new("document.txt.shadow");
//! let password = "secure_password";
//! let config = AesGcmConfig::production_config();
//! 
//! encrypt_single_file_with_config(input, encrypted, password, false, &config)?;
//! 
//! // Decrypt it back
//! let decrypted = Path::new("document_restored.txt");
//! decrypt_single_file_with_config(encrypted, decrypted, password, &config)?;
//! # Ok(())
//! # }
//! ```
//! 
//! # Security Guarantees
//! 
//! Shadow provides the following security properties:
//! 
//! - **Confidentiality**: File contents are encrypted with authenticated encryption
//! - **Integrity**: Tampering is detected through authentication tags
//! - **Forward secrecy**: Each file uses unique salts and nonces
//! - **Key security**: Keys are derived using Argon2id with secure parameters
//! - **Memory safety**: Sensitive data is zeroized after use
//! - **Filename privacy**: Optional obfuscation hides original filenames
//! 
//! # Algorithm Support
//! 
//! Current algorithm support includes:
//! - **AES-256-GCM**: High-performance authenticated encryption (default)
//! - **XChaCha20-Poly1305**: Extended nonce authenticated encryption
//! - **Argon2id**: Memory-hard key derivation function
//! - **HKDF-SHA256**: Key expansion and derivation
//! - **HMAC-SHA256**: Message authentication for filename obfuscation

// Public modules for use cases (these contain everything needed for each binary)
pub mod encryption;
pub mod decryption;
pub mod listing;
pub mod viewing;
pub mod editing;
pub mod migration;

// Shared functionality used across all use cases
pub mod shared;

// Re-export commonly used types for convenience
pub use shared::{CryptoError, Header, FileMetadata, AlgorithmId};
pub use shared::core::crypto::{SecretVec, KeyMaterial};

// Re-export versioning types for migration and compatibility
pub use shared::{VersionedHeader, HeaderV1, detect_version, CompatibilityMatrix};
pub use shared::{AnyHeader, VersionMigrator, MigrationPlan, MigrationStep, MigrationOperation};