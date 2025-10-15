//! Crypto vertical slice - all cryptography-related functionality.

pub mod types;
pub mod session;
pub mod operations;

// Use real crypto operations for production
pub use operations::*;

// Re-export commonly used types
pub use types::{AlgorithmId, SecureBox, KeyMaterial, KeyDerivationParams};
pub use session::CryptoSession;