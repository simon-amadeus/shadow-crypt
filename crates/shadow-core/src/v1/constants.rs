// shadow-core/src/v1/constants.rs
// Shadow file format version 1.0 constants
// All v1-specific constants and specifications

/// Magic bytes identifying Shadow encrypted files - version 1.0
pub const MAGIC: &[u8; 8] = b"SHADOW01";

/// Algorithm identifiers for v1 (re-exported from crypto module)
pub use super::crypto::algorithms::XCHACHA20_POLY1305 as ALGORITHM_XCHACHA20_POLY1305;

/// Filename encoding flags for v1
pub const FILENAME_PLAINTEXT: u8 = 0x00;
pub const FILENAME_ENCRYPTED: u8 = 0x01;

/// Size constraints for version 1.0
pub const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
pub const MAX_FILENAME_LENGTH: usize = 255;
pub const MIN_HEADER_SIZE: usize = 8 + 1 + 1 + 32 + 1 + 16 + 24; // Without filename data

/// Cryptographic parameters for version 1.0 (re-exported from crypto module)
pub use super::crypto::params::{
    HASH_SIZE, KEY_SIZE, NONCE_SIZE, SALT_SIZE,
};
