//! Algorithm management for Shadow encryption
//! 
//! This module provides algorithm-specific implementations and trait-based configuration
//! system for different cryptographic algorithms used in Shadow.
//!
//! # Configuration System Overview
//!
//! The configuration system provides algorithm-agnostic abstractions through traits:
//!
//! - [`KeyDerivationConfig`] - Password-based key derivation interface
//! - [`EncryptionConfig`] - Algorithm-specific parameters
//! - [`CryptoConfig`] - Combined configuration interface  
//! - [`ConfigProvider`] - Dependency injection pattern
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use shadow_crypt::shared::algorithms::{
//!     AesGcmConfig, DefaultConfigProvider, encrypt_with_provider
//! };
//! use std::path::Path;
//!
//! // Create a test configuration provider
//! let provider = DefaultConfigProvider::<AesGcmConfig>::test();
//! let input = Path::new("input.txt");
//! let output = Path::new("output.shadow");
//!
//! // Encrypt a file with dependency injection
//! encrypt_with_provider(&input, &output, "password", false, &provider)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Migration from Legacy Patterns
//!
//! **Old Pattern** (manual parameter injection):
//! ```rust,no_run
//! # use shadow_crypt::shared::algorithms::aes_gcm::Argon2Params;
//! # use shadow_crypt::encryption::encrypt_single_file_with_config;
//! # use shadow_crypt::shared::algorithms::{AesGcmConfig, DefaultConfigProvider, ConfigProvider};
//! # use std::path::Path;
//! # let input = Path::new("input.txt");
//! # let output = Path::new("output.shadow");
//! # let password = "password";
//! let provider = DefaultConfigProvider::<AesGcmConfig>::test();
//! encrypt_single_file_with_config(&input, &output, password, false, provider.config())?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! **New Pattern** (configuration providers):
//! ```rust,no_run
//! # use shadow_crypt::shared::algorithms::{AesGcmConfig, DefaultConfigProvider, encrypt_with_provider};
//! # use std::path::Path;
//! # let input = Path::new("input.txt");  
//! # let output = Path::new("output.shadow");
//! # let password = "password";
//! let provider = DefaultConfigProvider::<AesGcmConfig>::test();
//! encrypt_with_provider(&input, &output, password, false, &provider)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod aes_gcm;
pub mod xchacha20_poly1305;
pub mod selection;
pub mod registry;
pub mod constants;
pub mod config;
pub mod aes_gcm_config;
pub mod xchacha20_config;
pub mod generic_ops;
pub mod test_examples;

// Re-export commonly used types and functions for algorithm management
pub use selection::Algorithm;
pub use registry::{AlgorithmCapability, get_available_algorithms, get_algorithm_capability, is_algorithm_available, select_best_algorithm};
pub use constants::{AlgorithmId, CURRENT_VERSION, MIN_SUPPORTED_VERSION, MAX_SUPPORTED_VERSION, VersionInfo, MAX_FILENAME_LENGTH, MAX_DIRECTORY_PATH_LENGTH, MAX_METADATA_LENGTH};

// Re-export configuration system for easy access
pub use config::{KeyDerivationConfig, EncryptionConfig, CryptoConfig, ConfigProvider, DefaultConfigProvider};
pub use aes_gcm_config::AesGcmConfig;
pub use xchacha20_config::XChaCha20Config;
pub use generic_ops::{encrypt_with_config, decrypt_with_config, encrypt_with_provider, decrypt_with_provider};

// Re-export AES-GCM functions for backward compatibility
pub use aes_gcm::{encrypt_aes_gcm, decrypt_aes_gcm, generate_secure_nonce as generate_aes_nonce, generate_random_key as generate_aes_key, derive_master_key as derive_aes_master_key, generate_salt, Argon2Params, MasterKeyManager as AesKeyManager};

// Re-export XChaCha20-Poly1305 functions 
pub use xchacha20_poly1305::{encrypt_xchacha20_poly1305, decrypt_xchacha20_poly1305, generate_secure_nonce as generate_xchacha_nonce, generate_random_key as generate_xchacha_key, derive_master_key as derive_xchacha_master_key, MasterKeyManager as XChaChaKeyManager};