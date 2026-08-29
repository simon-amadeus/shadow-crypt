//! Version 3 of the encryption protocol.
//!
//! Like v2 it uses XChaCha20-Poly1305 with Argon2id key derivation and
//! authenticates the fixed header fields as associated data, with distinct
//! domain-separation tags. Two things change:
//!
//! - **Streaming content.** The content is encrypted as a sequence of AEAD
//!   chunks (see [`stream`]) instead of one message, so files of any size
//!   can be processed with bounded memory. The per-chunk nonce carries a
//!   counter and a final-chunk flag, making reordering, truncation, and
//!   extension of the stream fail authentication.
//! - **Metadata envelope.** The header stores one encrypted envelope (see
//!   [`metadata`]) carrying the original filename plus optional mtime and
//!   Unix mode, instead of a bare filename ciphertext.
//!
//! The intended entry points are [`stream::StreamSealer::begin`] /
//! [`stream::StreamOpener`] for streaming, and [`file::EncryptedFile`] for
//! whole-bytes use.
//!
//! This module is deliberately independent of [`crate::v1`] and
//! [`crate::v2`]: the formats share no code, so changes to one can never
//! silently alter another.

use crate::algorithm::Algorithm;

/// Encryption and decryption primitives (AAD-authenticated).
pub mod crypt;

/// Encrypted file structures and whole-bytes seal/decrypt operations.
pub mod file;

/// File header structures, serialization, and header binding for AAD.
pub mod header;

/// Key derivation parameters and operations.
pub mod key;

/// Plaintext layout of the encrypted metadata envelope.
pub mod metadata;

/// Chunked (streaming) content encryption.
pub mod stream;

/// The AEAD algorithm used by every v3 file.
pub const ALGORITHM: Algorithm = Algorithm::XChaCha20Poly1305;

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use crate::{
        file::FileMetadata,
        memory::{SecureKey, SecureString},
        v3::{file::EncryptedFile, key::KeyDerivationParams},
    };

    fn test_metadata() -> FileMetadata {
        FileMetadata::new(
            SecureString::new("name.txt".to_string()),
            Some(UNIX_EPOCH + Duration::new(1_700_000_000, 500)),
            Some(0o640),
        )
    }

    fn derive_test_key(password: &[u8], salt: &[u8; 16]) -> SecureKey {
        let (key, _) = KeyDerivationParams::test_defaults()
            .derive_key(password, salt)
            .unwrap();
        key
    }

    /// Full round trip through the seal/decrypt façade, including
    /// serialization to raw bytes and back.
    #[test]
    fn seal_decrypt_round_trip_via_bytes() {
        let salt = [1u8; 16];
        let key = derive_test_key(b"password", &salt);

        let sealed = EncryptedFile::seal(
            &test_metadata(),
            b"hello streaming world",
            &key,
            KeyDerivationParams::test_defaults(),
            salt,
            [2u8; 16],
            [3u8; 24],
        )
        .unwrap();

        let parsed = EncryptedFile::from_bytes(&sealed.to_bytes()).unwrap();
        let decrypted = parsed.decrypt(&key).unwrap();

        assert_eq!(decrypted.filename().as_str(), "name.txt");
        assert_eq!(decrypted.content().as_slice(), b"hello streaming world");

        // The metadata round-trips through the header on its own.
        let metadata = parsed.header().decrypt_metadata(&key).unwrap();
        assert_eq!(metadata.mtime(), test_metadata().mtime());
        assert_eq!(metadata.mode(), Some(0o640));
    }

    #[test]
    fn empty_content_round_trip() {
        let salt = [1u8; 16];
        let key = derive_test_key(b"password", &salt);

        let sealed = EncryptedFile::seal(
            &test_metadata(),
            b"",
            &key,
            KeyDerivationParams::test_defaults(),
            salt,
            [2u8; 16],
            [3u8; 24],
        )
        .unwrap();

        let decrypted = EncryptedFile::from_bytes(&sealed.to_bytes())
            .unwrap()
            .decrypt(&key)
            .unwrap();
        assert!(decrypted.content().as_slice().is_empty());
    }

    #[test]
    fn seal_decrypt_with_wrong_key_fails() {
        let salt = [1u8; 16];
        let key = derive_test_key(b"password", &salt);
        let wrong_key = derive_test_key(b"wrong", &salt);

        let sealed = EncryptedFile::seal(
            &test_metadata(),
            b"content",
            &key,
            KeyDerivationParams::test_defaults(),
            salt,
            [2u8; 16],
            [3u8; 24],
        )
        .unwrap();

        assert!(sealed.decrypt(&wrong_key).is_err());
    }

    /// Truncating whole trailing chunks (not just corrupting bytes) must be
    /// detected via the final-chunk flag.
    #[test]
    fn truncated_content_fails() {
        let salt = [1u8; 16];
        let key = derive_test_key(b"password", &salt);

        let sealed = EncryptedFile::seal(
            &test_metadata(),
            b"some content",
            &key,
            KeyDerivationParams::test_defaults(),
            salt,
            [2u8; 16],
            [3u8; 24],
        )
        .unwrap();

        let mut bytes = sealed.to_bytes();
        // Strip the entire content stream, leaving only the valid header.
        bytes.truncate(sealed.header().header_length());
        let truncated = EncryptedFile::from_bytes(&bytes).unwrap();
        assert!(truncated.decrypt(&key).is_err());
    }
}
