//! Cryptographic primitives and secure operations
//! 
//! This module provides the core cryptographic functionality used throughout
//! the application, including AES-GCM encryption, Argon2 key derivation.
//! 
//! Note: Core security utilities (nonce tracking, timing analysis, secure memory)
//! have moved to shared::core::crypto for better organization.

pub mod aes;
pub mod argon2;

// Re-export commonly used types and functions
pub use aes::{encrypt_aes_gcm, decrypt_aes_gcm, generate_secure_nonce, generate_random_key};
pub use argon2::{derive_master_key, generate_salt, Argon2Params, MasterKeyManager};

// Re-export core crypto utilities for backward compatibility
pub use crate::shared::core::crypto::{SecretVec, KeyMaterial, check_nonce_reuse, validate_nonce_entropy, get_nonce_statistics, TimingAnalyzer, TimingAnalysisResult, run_timing_security_tests};