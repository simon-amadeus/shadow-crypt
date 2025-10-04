//! # Deprecated: Cryptographic Configuration Traits
//!
//! This module has been replaced by crypto_service.rs to fix clean architecture violations.
//! All traits have been moved to crypto_service.rs for proper layer separation.

// Re-export everything from crypto_service for compatibility during transition
pub use super::crypto_service::*;