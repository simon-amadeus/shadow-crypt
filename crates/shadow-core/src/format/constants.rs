// shadow-core/src/format/constants.rs
// All Shadow file format constants in one place
// Any change to the format specification requires changes only here

/// Current Shadow file format version
pub const SHADOW_FORMAT_VERSION: u8 = 1;

/// Magic bytes identifying Shadow encrypted files - version 1.0
pub const SHADOW_V1_MAGIC: &[u8; 8] = b"SHADOW01";

/// Algorithm identifiers
pub const ALGORITHM_XCHACHA20_POLY1305: u8 = 0x01;

/// Filename encoding flags
pub const FILENAME_PLAINTEXT: u8 = 0x00;
pub const FILENAME_ENCRYPTED: u8 = 0x01;

/// Size constraints for version 1.0
pub const V1_MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
pub const V1_MAX_FILENAME_LENGTH: usize = 255;
pub const V1_MIN_HEADER_SIZE: usize = 8 + 1 + 1 + 32 + 1 + 16 + 24; // Without filename data

/// Cryptographic parameters for version 1.0
pub const V1_KEY_SIZE: usize = 32;      // XChaCha20 key size
pub const V1_NONCE_SIZE: usize = 24;    // XChaCha20 nonce size  
pub const V1_SALT_SIZE: usize = 16;     // Argon2id salt size
pub const V1_HASH_SIZE: usize = 32;     // SHA-256 hash size

/// Format structure offsets (for parsing)
pub const OFFSET_MAGIC: usize = 0;
pub const OFFSET_ALGORITHM: usize = 8;
pub const OFFSET_FILENAME_FLAG: usize = 9;
pub const OFFSET_CONTENT_HASH: usize = 10;
pub const OFFSET_FILENAME_DATA: usize = 42;
// Note: Salt and nonce offsets depend on filename data length