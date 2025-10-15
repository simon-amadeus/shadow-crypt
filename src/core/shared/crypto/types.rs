//! Core cryptographic types - migrated from domain/shared.

use std::fmt;
use crate::core::shared::types::{CoreResult, CryptoError};
use zeroize::Zeroize;

// ============================================================================
// ALGORITHM IDENTIFICATION
// ============================================================================

/// Cryptographic algorithm identifier with stable IDs for file format compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AlgorithmId {
    AesGcm256 = 1,         // Legacy support
    XChaCha20Poly1305 = 2, // Current default
}

impl AlgorithmId {
    /// Get the recommended default algorithm.
    pub fn recommended() -> Self {
        AlgorithmId::XChaCha20Poly1305
    }

    /// Convert from numeric identifier.
    pub fn from_u16(id: u16) -> CoreResult<Self> {
        match id {
            1 => Ok(AlgorithmId::AesGcm256),
            2 => Ok(AlgorithmId::XChaCha20Poly1305),
            _ => Err(CryptoError::UnsupportedAlgorithm { algorithm_id: id }.into()),
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
        16 // 128-bit salt for all algorithms
    }

    /// Get authentication tag size in bytes.
    pub fn tag_size(self) -> usize {
        16 // 128-bit tag for all algorithms
    }
}

// ============================================================================
// SECURE MEMORY MANAGEMENT
// ============================================================================

/// Secure container that automatically zeroizes contents on drop.
pub struct SecureBox<T: Zeroize> {
    data: Box<T>,
}

impl<T: Zeroize> SecureBox<T> {
    /// Create a new SecureBox containing the given data.
    pub fn new(data: T) -> Self {
        Self {
            data: Box::new(data),
        }
    }
    
    /// Get a reference to the contained data.
    pub fn expose_secret(&self) -> &T {
        &self.data
    }
}

impl<T: Zeroize> Drop for SecureBox<T> {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl<T: Zeroize + Clone> Clone for SecureBox<T> {
    fn clone(&self) -> Self {
        Self::new(self.data.as_ref().clone())
    }
}

impl<T: Zeroize> std::fmt::Debug for SecureBox<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBox")
            .field("data", &"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// KEY MATERIAL & DERIVATION
// ============================================================================

/// Key derivation parameters for password-based key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDerivationParams {
    pub memory_cost: u32,      // Memory cost in KiB
    pub time_cost: u32,        // Time cost in iterations
    pub parallelism: u32,      // Number of threads
    pub output_length: usize,  // Output key length in bytes
}

impl KeyDerivationParams {
    pub const MIN_MEMORY_COST_PRODUCTION: u32 = 1_048_576; // 1 GiB
    pub const MIN_MEMORY_COST_GENERAL: u32 = 262_144;      // 256 MiB
    pub const MIN_TIME_COST_PRODUCTION: u32 = 5;
    pub const MIN_TIME_COST_GENERAL: u32 = 3;
    pub const MAX_PARALLELISM: u32 = 16;
    pub const RECOMMENDED_OUTPUT_LENGTH: usize = 32;
    
    /// Create production-strength parameters.
    pub fn production() -> Self {
        Self {
            memory_cost: Self::MIN_MEMORY_COST_PRODUCTION,
            time_cost: Self::MIN_TIME_COST_PRODUCTION,
            parallelism: num_cpus::get().min(Self::MAX_PARALLELISM as usize) as u32,
            output_length: Self::RECOMMENDED_OUTPUT_LENGTH,
        }
    }
    
    /// Create general-use parameters.
    pub fn general() -> Self {
        Self {
            memory_cost: Self::MIN_MEMORY_COST_GENERAL,
            time_cost: Self::MIN_TIME_COST_GENERAL,
            parallelism: num_cpus::get().min(Self::MAX_PARALLELISM as usize) as u32,
            output_length: Self::RECOMMENDED_OUTPUT_LENGTH,
        }
    }
}

/// Cryptographic key material container.
#[derive(Debug)]
pub struct KeyMaterial {
    pub encryption_key: SecureBox<[u8; 32]>,
    pub obfuscation_key: SecureBox<[u8; 32]>,
}

impl KeyMaterial {
    /// Create new key material from derived keys.
    pub fn new(encryption_key: [u8; 32], obfuscation_key: [u8; 32]) -> Self {
        Self {
            encryption_key: SecureBox::new(encryption_key),
            obfuscation_key: SecureBox::new(obfuscation_key),
        }
    }
}