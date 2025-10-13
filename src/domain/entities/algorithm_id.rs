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

/// Algorithm identifier for cryptographic operations
/// 
/// Represents the business concept of algorithm selection, containing all domain logic
/// related to algorithm properties and capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AlgorithmId {
    XChaCha20Poly1305 = 1,
    AesGcm256 = 2,
}

impl AlgorithmId {
    /// Convert from u16 identifier
    pub fn from_u16(id: u16) -> Result<Self, DomainError> {
        match id {
            1 => Ok(AlgorithmId::XChaCha20Poly1305),
            2 => Ok(AlgorithmId::AesGcm256),
            _ => Err(DomainError::unsupported_algorithm(id)),
        }
    }

    /// Convert from u8 identifier (for compatibility with legacy code)
    pub fn from_u8(id: u8) -> Result<Self, DomainError> {
        Self::from_u16(id as u16)
    }

    /// Convert to u16 identifier for serialization
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Convert to u8 identifier (for compatibility with legacy code)
    pub fn as_u8(self) -> u8 {
        let id = self as u16;
        if id > 255 {
            panic!("Algorithm ID {} too large for u8", id);
        }
        id as u8
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
            AlgorithmId::XChaCha20Poly1305 => 24, // 192 bits
            AlgorithmId::AesGcm256 => 12,         // 96 bits
        }
    }
}
