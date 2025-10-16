// shadow-core/src/constants.rs
// Constants used throughout the Shadow encryption system
// All format constants live here to ensure consistency and single source of truth

/// Magic bytes identifying Shadow encrypted files
pub const MAGIC_BYTES: &[u8; 8] = b"SHADOW01";

/// Algorithm identifier for XChaCha20-Poly1305
pub const ALGORITHM_ID_XCHACHA20_POLY1305: u8 = 0x01;

/// Obfuscation flag values
pub const OBFUSCATION_FLAG_DISABLED: u8 = 0x00;
pub const OBFUSCATION_FLAG_ENABLED: u8 = 0x01;

/// Size limits and constraints
pub const MIN_HEADER_SIZE: usize = 8 + 1 + 1 + 32 + 1 + 16 + 24; // Without filename data
pub const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
pub const MAX_FILENAME_LENGTH: usize = 255;

/// Cryptographic sizes
pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 24;
pub const SALT_SIZE: usize = 16;
pub const HASH_SIZE: usize = 32;

/// Minimum password strength requirements
pub const MIN_PASSWORD_LENGTH: usize = 8;
pub const MIN_PASSWORD_ENTROPY_BITS: f64 = 32.0;