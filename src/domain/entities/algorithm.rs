//! Cryptographic algorithm identifiers and properties.
//!
//! Defines supported encryption algorithms with stable identifiers for file format
//! compatibility. Algorithm IDs persist in file headers and must remain constant
//! across releases to ensure encrypted files remain accessible.

use crate::domain::errors::DomainError;
use std::fmt;

/// Cryptographic algorithm identifier.
/// 
/// Each algorithm has a stable numeric ID that persists in file headers.
/// IDs must never change to maintain backward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AlgorithmId {
    AesGcm256 = 1,         // Legacy support
    XChaCha20Poly1305 = 2, // Current default
}

impl AlgorithmId {
    /// Get the default algorithm.
    pub fn recommended() -> Self {
        AlgorithmId::XChaCha20Poly1305
    }

    /// Convert from numeric identifier.
    pub fn from_u16(id: u16) -> Result<Self, DomainError> {
        match id {
            1 => Ok(AlgorithmId::AesGcm256),
            2 => Ok(AlgorithmId::XChaCha20Poly1305),
            _ => Err(DomainError::unsupported_algorithm(id)),
        }
    }

    /// Convert to numeric identifier for serialization.
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Get algorithm name.
    pub fn name(self) -> &'static str {
        match self {
            AlgorithmId::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            AlgorithmId::AesGcm256 => "AES-256-GCM",
        }
    }

    /// Get required key size in bytes.
    pub fn key_size(self) -> usize {
        match self {
            AlgorithmId::XChaCha20Poly1305 => 32, // 256 bits
            AlgorithmId::AesGcm256 => 32,         // 256 bits
        }
    }

    /// Get required nonce size in bytes.
    pub fn nonce_size(self) -> usize {
        match self {
            AlgorithmId::XChaCha20Poly1305 => 24, // 192 bits (extended nonce)
            AlgorithmId::AesGcm256 => 12,         // 96 bits (standard GCM)
        }
    }

    /// Get salt size for key derivation in bytes.
    pub fn salt_size(self) -> usize {
        match self {
            AlgorithmId::XChaCha20Poly1305 => 16, // 128-bit salt
            AlgorithmId::AesGcm256 => 16,         // 128-bit salt
        }
    }

    /// Get authentication tag size in bytes.
    pub fn tag_size(self) -> usize {
        match self {
            AlgorithmId::XChaCha20Poly1305 => 16, // Poly1305 tag
            AlgorithmId::AesGcm256 => 16,         // GCM tag
        }
    }

    /// Check if algorithm supports streaming encryption.
    pub fn supports_streaming(self) -> bool {
        match self {
            AlgorithmId::XChaCha20Poly1305 => true,
            AlgorithmId::AesGcm256 => true,
        }
    }

    /// Check if algorithm supports associated data.
    pub fn supports_aad(self) -> bool {
        match self {
            AlgorithmId::XChaCha20Poly1305 => true,
            AlgorithmId::AesGcm256 => true,
        }
    }

    /// Get maximum plaintext size supported in bytes.
    pub fn max_plaintext_size(self) -> Option<u64> {
        match self {
            // ChaCha20 limit: 2^38 bytes per key/nonce pair
            AlgorithmId::XChaCha20Poly1305 => Some(274_877_906_944), // ~256 GB
            // AES-GCM limit: 2^36 bytes per key/nonce pair  
            AlgorithmId::AesGcm256 => Some(68_719_476_736),          // ~64 GB
        }
    }
}

impl fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}
