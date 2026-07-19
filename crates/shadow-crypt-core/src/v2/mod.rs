//! Version 2 of the encryption protocol.
//!
//! Like v1 it uses XChaCha20-Poly1305 with Argon2id key derivation and an
//! identical header layout (with version byte 2). The difference is that v2
//! authenticates the header: every AEAD operation binds the fixed header
//! fields (magic, version, salt, KDF parameters, both nonces) as associated
//! data, with distinct domain-separation tags for the filename and the
//! content. This prevents an attacker from swapping the filename and content
//! ciphertexts within a file or tampering with header fields without
//! detection.
//!
//! This module is deliberately independent of [`crate::v1`]: the two formats
//! share no code, so changes to one can never silently alter the other.

/// Encryption and decryption primitives (AAD-authenticated).
pub mod crypt;

/// Encrypted file structures.
pub mod file;

/// Encrypted file operations.
pub mod file_ops;

/// File header structures and header binding for AAD.
pub mod header;

/// File header serialization and deserialization.
pub mod header_ops;

/// Key derivation parameters.
pub mod key;

/// Key derivation operations.
pub mod key_ops;
