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
//! This format is legacy: new files are always written as v3, and v2
//! support exists to decrypt and list existing files. The intended entry
//! points are [`file::EncryptedFile::seal`] (kept for round-trip tests) and
//! [`file::EncryptedFile::decrypt`], which own the AEAD choreography
//! (nonce/ciphertext pairing, domain separation, header binding); the
//! submodules expose the underlying pieces.
//!
//! This module is deliberately independent of [`crate::v1`]: the two formats
//! share no code, so changes to one can never silently alter the other.

use crate::algorithm::Algorithm;

/// Encryption and decryption primitives (AAD-authenticated).
pub mod crypt;

/// Encrypted file structures and whole-file seal/decrypt operations.
pub mod file;

/// File header structures, serialization, and header binding for AAD.
pub mod header;

/// Key derivation parameters and operations.
pub mod key;

/// The AEAD algorithm used by every v2 file.
pub const ALGORITHM: Algorithm = Algorithm::XChaCha20Poly1305;

#[cfg(test)]
mod tests {
    use crate::{
        file::PlaintextFile,
        memory::{SecureBytes, SecureString},
        v2::{
            crypt::{decrypt_bytes, encrypt_bytes},
            file::EncryptedFile,
            header::{AadPurpose, HeaderBinding},
            key::KeyDerivationParams,
        },
    };

    /// The v1 weakness this format fixes: filename and content ciphertexts
    /// are encrypted under the same key, so without domain separation an
    /// attacker could swap the (nonce, ciphertext) pairs and both would still
    /// authenticate. In v2, a ciphertext produced for one purpose must never
    /// decrypt as the other.
    #[test]
    fn swapped_filename_and_content_ciphertexts_fail_authentication() {
        let key = [9u8; 32];
        let salt = [1u8; 16];
        let params = KeyDerivationParams::test_defaults();
        let content_nonce = [2u8; 24];
        let filename_nonce = [3u8; 24];
        let binding = HeaderBinding::new(&salt, &params, &content_nonce, &filename_nonce);

        let (filename_ct, _) = encrypt_bytes(
            b"secret-name.txt",
            &key,
            &filename_nonce,
            &binding.aad(AadPurpose::Filename),
        )
        .unwrap();
        let (content_ct, _) = encrypt_bytes(
            b"file content",
            &key,
            &content_nonce,
            &binding.aad(AadPurpose::Content),
        )
        .unwrap();

        // Attacker swaps the pairs: content slot holds the filename pair and
        // vice versa. The header binding still matches (nonces unchanged as a
        // set), so only the purpose tag distinguishes the two operations.
        let swapped_content = decrypt_bytes(
            &filename_ct,
            &key,
            &filename_nonce,
            &binding.aad(AadPurpose::Content),
        );
        let swapped_filename = decrypt_bytes(
            &content_ct,
            &key,
            &content_nonce,
            &binding.aad(AadPurpose::Filename),
        );

        assert!(swapped_content.is_err());
        assert!(swapped_filename.is_err());
    }

    /// Tampering with any authenticated header field must break decryption.
    #[test]
    fn tampered_header_fields_fail_authentication() {
        let key = [9u8; 32];
        let salt = [1u8; 16];
        let params = KeyDerivationParams::test_defaults();
        let content_nonce = [2u8; 24];
        let filename_nonce = [3u8; 24];
        let binding = HeaderBinding::new(&salt, &params, &content_nonce, &filename_nonce);

        let (content_ct, _) = encrypt_bytes(
            b"file content",
            &key,
            &content_nonce,
            &binding.aad(AadPurpose::Content),
        )
        .unwrap();

        // Downgrade the KDF parameters in the header.
        let weak_params = KeyDerivationParams::new(8, 1, 1, 32);
        let tampered = HeaderBinding::new(&salt, &weak_params, &content_nonce, &filename_nonce);
        assert!(
            decrypt_bytes(
                &content_ct,
                &key,
                &content_nonce,
                &tampered.aad(AadPurpose::Content),
            )
            .is_err()
        );

        // Swap in a different salt.
        let other_salt = [7u8; 16];
        let tampered = HeaderBinding::new(&other_salt, &params, &content_nonce, &filename_nonce);
        assert!(
            decrypt_bytes(
                &content_ct,
                &key,
                &content_nonce,
                &tampered.aad(AadPurpose::Content),
            )
            .is_err()
        );
    }

    /// Full round trip through the seal/decrypt façade, including
    /// serialization to raw bytes and back.
    #[test]
    fn seal_decrypt_round_trip_via_bytes() {
        let salt = [1u8; 16];
        let params = KeyDerivationParams::test_defaults();
        let (key, _) = params.derive_key(b"password", &salt).unwrap();

        let plaintext_file = PlaintextFile::new(
            SecureString::new("name.txt".to_string()),
            SecureBytes::new(b"hello".to_vec()),
        );

        let sealed =
            EncryptedFile::seal(&plaintext_file, &key, params, salt, [2u8; 24], [3u8; 24]).unwrap();

        let parsed = EncryptedFile::from_bytes(&sealed.to_bytes()).unwrap();
        let decrypted = parsed.decrypt(&key).unwrap();

        assert_eq!(decrypted.filename().as_str(), "name.txt");
        assert_eq!(decrypted.content().as_slice(), b"hello");
    }

    /// Decrypting with a key derived from the wrong password must fail.
    #[test]
    fn seal_decrypt_with_wrong_key_fails() {
        let salt = [1u8; 16];
        let params = KeyDerivationParams::test_defaults();
        let (key, _) = params.derive_key(b"password", &salt).unwrap();
        let (wrong_key, _) = params.derive_key(b"wrong", &salt).unwrap();

        let plaintext_file = PlaintextFile::new(
            SecureString::new("name.txt".to_string()),
            SecureBytes::new(b"hello".to_vec()),
        );

        let sealed =
            EncryptedFile::seal(&plaintext_file, &key, params, salt, [2u8; 24], [3u8; 24]).unwrap();

        assert!(sealed.decrypt(&wrong_key).is_err());
    }
}
