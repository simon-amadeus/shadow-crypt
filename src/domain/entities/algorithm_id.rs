//! # Domain Cryptographic Algorithm Abstractions
//!
//! This module defines the core cryptographic abstractions that belong in the domain layer.
//! These traits represent business rules and capabilities, not implementation details.

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
            AlgorithmId::XChaCha20Poly1305 => 24, // 192 bits
            AlgorithmId::AesGcm256 => 12,         // 96 bits
        }
    }
}