// shadow-core/src/v1/constants.rs
// Shadow file format version 1.0 constants
// All v1-specific constants and specifications

/// Magic bytes identifying Shadow encrypted files - version 1.0
pub const MAGIC: &[u8; 8] = b"SHADOW01";

/// Algorithm identifiers for v1
pub const ALGORITHM_XCHACHA20_POLY1305: u8 = 0x01;

/// Filename encoding flags for v1
pub const FILENAME_PLAINTEXT: u8 = 0x00;
pub const FILENAME_ENCRYPTED: u8 = 0x01;

/// Size constraints for version 1.0
pub const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
pub const MAX_FILENAME_LENGTH: usize = 255;

/// Minimum header size calculation - hardcoded for simplicity
/// 8 (magic) + 1 (algo) + 1 (obfuscation) + 32 (hash) + 1 (filename_len) + 16 (salt) + 24 (nonce)
pub const MIN_HEADER_SIZE: usize = 83;
