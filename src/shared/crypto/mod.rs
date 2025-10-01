//! Cryptographic operations dispatcher
//! 
//! This module provides a compatibility layer that dispatches to the appropriate
//! algorithm-specific implementations. Core security utilities have moved to
//! shared::core::crypto for better organization.

// Re-export algorithm implementations for backward compatibility
pub use crate::shared::algorithms::{encrypt_aes_gcm, decrypt_aes_gcm, generate_secure_nonce, generate_random_key, derive_master_key, generate_salt, Argon2Params, MasterKeyManager};

// Re-export core crypto utilities for backward compatibility
pub use crate::shared::core::crypto::{SecretVec, KeyMaterial, check_nonce_reuse, validate_nonce_entropy, get_nonce_statistics, TimingAnalyzer, TimingAnalysisResult, run_timing_security_tests};