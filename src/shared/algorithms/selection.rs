//! Algorithm selection logic for Shadow encryption
//! 
//! This module provides functionality to select appropriate cryptographic
//! algorithms based on requirements and system capabilities.

use crate::shared::core::errors::CryptoError;

/// Supported cryptographic algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    AES256GCM,
    // Future algorithms will be added here
    // ChaCha20Poly1305,
    // Kyber1024AES256,
}

impl Algorithm {
    /// Get the current default algorithm
    pub fn default() -> Self {
        Algorithm::AES256GCM
    }
    
    /// Get algorithm from identifier
    pub fn from_id(id: u16) -> Result<Self, CryptoError> {
        match id {
            1 => Ok(Algorithm::AES256GCM),
            _ => Err(CryptoError::UnsupportedAlgorithm(id)),
        }
    }
    
    /// Get identifier for this algorithm
    pub fn to_id(self) -> u16 {
        match self {
            Algorithm::AES256GCM => 1,
        }
    }
    
    /// Get human-readable name
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::AES256GCM => "AES-256-GCM",
        }
    }
    
    /// Get key size in bytes
    pub fn key_size(self) -> usize {
        match self {
            Algorithm::AES256GCM => 32,
        }
    }
    
    /// Get nonce size in bytes
    pub fn nonce_size(self) -> usize {
        match self {
            Algorithm::AES256GCM => 12,
        }
    }
}