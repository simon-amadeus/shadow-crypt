//! # Cryptographic Configuration Providers
//!
//! Concrete implementations of cryptographic configuration traits
//! for supported algorithms (XChaCha20-Poly1305, AES-256-GCM).

pub mod xchacha20;

pub use xchacha20::XChaCha20Provider;