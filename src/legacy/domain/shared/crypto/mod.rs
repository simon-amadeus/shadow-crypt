//! # Crypto Topic - All Cryptography-Related Concerns
//!
//! This module groups all cryptography-related domain concepts:
//! - Algorithms and configuration
//! - Keys and key derivation  
//! - Hashing and memory management
//! - Crypto sessions
//!
//! Organized by cohesion rather than technical patterns.

// ============================================================================
// ALGORITHM & CONFIGURATION
// ============================================================================

pub mod algorithm;

// ============================================================================  
// KEY MANAGEMENT
// ============================================================================

pub mod key;
pub mod memory;

// ============================================================================
// CONTENT INTEGRITY 
// ============================================================================

pub mod hash;

// ============================================================================
// CRYPTO SESSIONS
// ============================================================================

pub mod session;

// ============================================================================
// PUBLIC API - ORGANIZED BY CONCERN
// ============================================================================

// Algorithm identification
pub use algorithm::AlgorithmId;

// Key management
pub use key::{KeyMaterial, KeyDerivationParams};
pub use memory::SecureBox;

// Content integrity
pub use hash::{ContentHash, ContentHasher, CONTENT_HASH_SIZE};

// Sessions
pub use session::CryptoSession;