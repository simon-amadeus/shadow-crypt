//! Cryptographic primitives and secure operations
//! 
//! This module provides the core cryptographic functionality used throughout
//! the application, including AES-GCM encryption, Argon2 key derivation,
//! secure memory handling, nonce reuse protection, timing attack detection,
//! and other security primitives.

pub mod aes;
pub mod argon2;
pub mod secure_memory;
pub mod nonce_tracking;
pub mod timing_analysis;

// Re-export commonly used types and functions
pub use aes::{encrypt_aes_gcm, decrypt_aes_gcm, generate_secure_nonce, generate_random_key};
pub use argon2::{derive_master_key, generate_salt, Argon2Params, MasterKeyManager};
pub use secure_memory::{SecretVec, KeyMaterial};
pub use nonce_tracking::{check_nonce_reuse, validate_nonce_entropy, get_nonce_statistics};
pub use timing_analysis::{TimingAnalyzer, TimingAnalysisResult, run_timing_security_tests};