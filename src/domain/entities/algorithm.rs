//! # Domain Cryptographic Algorithm Abstractions
//!
//! This module defines the core cryptographic abstractions that belong in the domain layer.
//! These traits represent business rules and capabilities, not implementation details.
//!
//! ## Algorithm Registry
//!
//! The `AlgorithmId` enum serves as a stable registry for all supported cryptographic
//! algorithms. Each algorithm receives a unique `u16` identifier that:
//!
//! - **Persists in file headers** for format compatibility
//! - **Remains stable across releases** to ensure file accessibility
//! - **Provides systematic allocation** to prevent ID conflicts
//! - **Supports 65,535 algorithms** for maximum future-proofing
//!
//! ## Adding New Algorithms
//!
//! When adding a new algorithm:
//! 1. Add new variant with next available ID number
//! 2. Update `from_u16()` conversion method
//! 3. Update `name()`, `key_size()`, and `nonce_size()` methods
//! 4. Update factory pattern in `infrastructure::crypto::factory`
//!
//! **Important**: Never change existing ID numbers as this would break file compatibility.
//!
//! ## Post-Quantum Considerations
//!
//! Future post-quantum algorithms can be added using the same pattern:
//! - Larger key sizes supported via `key_size()` method
//! - Extended nonces supported via `nonce_size()` method  
//! - Algorithm-specific metadata via TLV headers
//! - Hybrid algorithms as single enum variants

use crate::domain::errors::DomainError;
use std::fmt;

/// Algorithm identifier for cryptographic operations
/// 
/// Represents the business concept of algorithm selection, containing all domain logic
/// related to algorithm properties and capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AlgorithmId {
    AesGcm256 = 1,         // Legacy algorithm
    XChaCha20Poly1305 = 2, // Current recommended algorithm
}

impl AlgorithmId {
    /// Get the current recommended algorithm
    pub fn recommended() -> Self {
        AlgorithmId::XChaCha20Poly1305
    }

    /// Convert from u16 identifier
    pub fn from_u16(id: u16) -> Result<Self, DomainError> {
        match id {
            1 => Ok(AlgorithmId::AesGcm256),
            2 => Ok(AlgorithmId::XChaCha20Poly1305),
            _ => Err(DomainError::unsupported_algorithm(id)),
        }
    }

    /// Convert to u16 identifier for serialization
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Get human-readable algorithm name
    pub fn name(self) -> &'static str {
        match self {
            AlgorithmId::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            AlgorithmId::AesGcm256 => "AES-256-GCM",
        }
    }

    /// Get algorithm-specific key size in bytes
    pub fn key_size(self) -> usize {
        match self {
            AlgorithmId::XChaCha20Poly1305 => 32, // 256 bits
            AlgorithmId::AesGcm256 => 32,         // 256 bits
        }
    }

    /// Get algorithm-specific nonce size in bytes
    pub fn nonce_size(self) -> usize {
        match self {
            AlgorithmId::XChaCha20Poly1305 => 24, // 192 bits (extended nonce)
            AlgorithmId::AesGcm256 => 12,         // 96 bits (standard GCM)
        }
    }

    /// Get recommended salt size for key derivation
    pub fn salt_size(self) -> usize {
        match self {
            AlgorithmId::XChaCha20Poly1305 => 16, // 128-bit salt for Argon2id
            AlgorithmId::AesGcm256 => 16,         // 128-bit salt for Argon2id
        }
    }

    /// Get authentication tag size in bytes
    pub fn tag_size(self) -> usize {
        match self {
            AlgorithmId::XChaCha20Poly1305 => 16, // Poly1305 tag
            AlgorithmId::AesGcm256 => 16,         // GCM tag
        }
    }

    /// Check if algorithm supports streaming encryption
    pub fn supports_streaming(self) -> bool {
        match self {
            AlgorithmId::XChaCha20Poly1305 => true,
            AlgorithmId::AesGcm256 => true,
        }
    }

    /// Check if algorithm supports associated data
    pub fn supports_aad(self) -> bool {
        match self {
            AlgorithmId::XChaCha20Poly1305 => true,
            AlgorithmId::AesGcm256 => true,
        }
    }

    /// Get maximum plaintext size supported by algorithm
    pub fn max_plaintext_size(self) -> Option<u64> {
        match self {
            // ChaCha20 can encrypt up to 2^38 bytes per key/nonce pair
            AlgorithmId::XChaCha20Poly1305 => Some(274_877_906_944), // ~256 GB
            // AES-GCM can encrypt up to 2^36 bytes per key/nonce pair  
            AlgorithmId::AesGcm256 => Some(68_719_476_736),          // ~64 GB
        }
    }
}

impl fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}
