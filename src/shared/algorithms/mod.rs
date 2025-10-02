//! Algorithm management for Shadow encryption
//! 
//! This module provides algorithm-specific implementations and management functionality
//! for different cryptographic algorithms used in Shadow.

pub mod aes_gcm;
pub mod xchacha20_poly1305;
pub mod selection;
pub mod registry;
pub mod constants;
pub mod config;
pub mod aes_gcm_config;
pub mod generic_ops;
pub mod test_examples;

// Re-export commonly used types and functions
pub use selection::Algorithm;
pub use registry::{AlgorithmCapability, get_available_algorithms, get_algorithm_capability, is_algorithm_available, select_best_algorithm};
pub use constants::{AlgorithmId, CURRENT_VERSION, MIN_SUPPORTED_VERSION, MAX_SUPPORTED_VERSION, VersionInfo, MAX_FILENAME_LENGTH, MAX_DIRECTORY_PATH_LENGTH, MAX_METADATA_LENGTH};

// Re-export configuration traits and types
pub use config::{KeyDerivationConfig, EncryptionConfig, CryptoConfig, ConfigProvider, DefaultConfigProvider};
pub use aes_gcm_config::AesGcmConfig;
pub use generic_ops::{encrypt_with_config, decrypt_with_config, encrypt_with_provider, decrypt_with_provider};

// Re-export AES-GCM functions for backward compatibility
pub use aes_gcm::{encrypt_aes_gcm, decrypt_aes_gcm, generate_secure_nonce as generate_aes_nonce, generate_random_key as generate_aes_key, derive_master_key as derive_aes_master_key, generate_salt, Argon2Params, MasterKeyManager as AesKeyManager};

// Re-export XChaCha20-Poly1305 functions 
pub use xchacha20_poly1305::{encrypt_xchacha20_poly1305, decrypt_xchacha20_poly1305, generate_secure_nonce as generate_xchacha_nonce, generate_random_key as generate_xchacha_key, derive_master_key as derive_xchacha_master_key, MasterKeyManager as XChaChaKeyManager};