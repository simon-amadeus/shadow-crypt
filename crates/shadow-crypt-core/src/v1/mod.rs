//! Version 1 of the encryption protocol.
//!
//! Uses XChaCha20-Poly1305 with Argon2id key derivation. Unlike v2, the
//! header fields are not authenticated. This format is legacy: new files are
//! always written as v2, and v1 support exists only to decrypt and list
//! existing files via [`file::EncryptedFile::decrypt`] and
//! [`header::FileHeader::decrypt_filename`].
//!
//! This module is deliberately independent of [`crate::v2`]: the two formats
//! share no code, so changes to one can never silently alter the other.

use crate::algorithm::Algorithm;

/// Encryption and decryption primitives.
pub mod crypt;

/// Encrypted file structures and whole-file decrypt operations.
pub mod file;

/// File header structures and serialization.
pub mod header;

/// Key derivation parameters and operations.
pub mod key;

/// The AEAD algorithm used by every v1 file.
pub const ALGORITHM: Algorithm = Algorithm::XChaCha20Poly1305;

#[cfg(test)]
mod tests {
    use crate::{
        memory::{SecureBytes, SecureString},
        v1::{
            crypt::encrypt_bytes,
            file::{EncryptedFile, PlaintextFile},
            header::FileHeader,
            key::KeyDerivationParams,
        },
    };

    /// Round trip through the decrypt façade against a manually assembled v1
    /// file, mirroring how existing v1 files were produced.
    #[test]
    fn decrypt_round_trip_via_bytes() {
        let salt = [1u8; 16];
        let params = KeyDerivationParams::test_defaults();
        let content_nonce = [2u8; 24];
        let filename_nonce = [3u8; 24];
        let (key, _) = params.derive_key(b"password", &salt).unwrap();

        let (filename_ct, _) = encrypt_bytes(b"name.txt", key.as_bytes(), &filename_nonce).unwrap();
        let (content_ct, _) = encrypt_bytes(b"hello", key.as_bytes(), &content_nonce).unwrap();

        let header = FileHeader::new(salt, params, content_nonce, filename_nonce, filename_ct);
        let file = EncryptedFile::new(header, content_ct);

        let parsed = EncryptedFile::from_bytes(&file.to_bytes()).unwrap();
        let decrypted = parsed.decrypt(&key).unwrap();

        assert_eq!(decrypted.filename().as_str(), "name.txt");
        assert_eq!(decrypted.content().as_slice(), b"hello");
    }

    /// Decrypting with a key derived from the wrong password must fail.
    #[test]
    fn decrypt_with_wrong_key_fails() {
        let salt = [1u8; 16];
        let params = KeyDerivationParams::test_defaults();
        let (key, _) = params.derive_key(b"password", &salt).unwrap();
        let (wrong_key, _) = params.derive_key(b"wrong", &salt).unwrap();

        let (filename_ct, _) = encrypt_bytes(b"name.txt", key.as_bytes(), &[3u8; 24]).unwrap();
        let (content_ct, _) = encrypt_bytes(b"hello", key.as_bytes(), &[2u8; 24]).unwrap();

        let header = FileHeader::new(salt, params, [2u8; 24], [3u8; 24], filename_ct);
        let file = EncryptedFile::new(header, content_ct);

        assert!(file.decrypt(&wrong_key).is_err());
    }

    // PlaintextFile is referenced so the shared structure stays exercised
    // even though v1 files are never sealed anymore.
    #[test]
    fn plaintext_file_accessors() {
        let file = PlaintextFile::new(
            SecureString::new("a.txt".to_string()),
            SecureBytes::new(vec![1, 2, 3]),
        );
        assert_eq!(file.filename().as_str(), "a.txt");
        assert_eq!(file.content().as_slice(), &[1, 2, 3]);
    }
}
