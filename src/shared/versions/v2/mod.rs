//! Shadow file format version 2
//! 
//! Version 2 introduces support for:
//! - Variable-length nonces (supporting XChaCha20-Poly1305's 24-byte nonces)
//! - Enhanced algorithm support including ChaCha20Poly1305
//! - Backward compatibility with V1 decryption

pub mod header;
pub mod detection;
pub mod dispatch;

pub use header::{HeaderV2, MAGIC_NUMBER_V2, VERSION_V2};
pub use detection::is_v2_file;
pub use dispatch::DispatchV2;