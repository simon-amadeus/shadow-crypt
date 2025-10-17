// shadow-core/src/crypto/algorithms/xchacha20_poly1305/constants.rs
// XChaCha20-Poly1305 algorithm constants

/// Algorithm identifier for XChaCha20-Poly1305
pub const ALGORITHM_ID: u8 = 0x01;

/// XChaCha20 key size in bytes
pub const KEY_SIZE: usize = 32;

/// XChaCha20 nonce size in bytes  
pub const NONCE_SIZE: usize = 24;