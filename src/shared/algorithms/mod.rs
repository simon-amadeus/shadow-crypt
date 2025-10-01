//! Algorithm management for Shadow encryption
//! 
//! This module provides algorithm-specific implementations and management functionality
//! for different cryptographic algorithms used in Shadow.

pub mod aes_gcm;
pub mod selection;
pub mod registry;
pub mod constants;

// Re-export commonly used types and functions
pub use selection::Algorithm;
pub use registry::{AlgorithmCapability, get_available_algorithms, get_algorithm_capability, is_algorithm_available, select_best_algorithm};
pub use constants::{AlgorithmId, CURRENT_VERSION, MIN_SUPPORTED_VERSION, MAX_SUPPORTED_VERSION, VersionInfo, MAX_FILENAME_LENGTH, MAX_DIRECTORY_PATH_LENGTH, MAX_METADATA_LENGTH};

// Re-export AES-GCM functions for backward compatibility
pub use aes_gcm::{encrypt_aes_gcm, decrypt_aes_gcm, generate_secure_nonce, generate_random_key, derive_master_key, generate_salt, Argon2Params, MasterKeyManager};