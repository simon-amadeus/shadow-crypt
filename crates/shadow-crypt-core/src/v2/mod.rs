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

#[cfg(test)]
mod tests {
    use crate::v2::{
        crypt::{decrypt_bytes, encrypt_bytes},
        header::{AadPurpose, FileHeader, HeaderBinding},
        key::KeyDerivationParams,
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

    /// Full round trip through header construction, exactly as the shell does it.
    #[test]
    fn header_round_trip_decrypts_with_header_binding() {
        let key = [4u8; 32];
        let salt = [1u8; 16];
        let params = KeyDerivationParams::test_defaults();
        let content_nonce = [2u8; 24];
        let filename_nonce = [3u8; 24];
        let binding = HeaderBinding::new(&salt, &params, &content_nonce, &filename_nonce);

        let (filename_ct, _) = encrypt_bytes(
            b"name.txt",
            &key,
            &filename_nonce,
            &binding.aad(AadPurpose::Filename),
        )
        .unwrap();
        let (content_ct, _) = encrypt_bytes(
            b"hello",
            &key,
            &content_nonce,
            &binding.aad(AadPurpose::Content),
        )
        .unwrap();

        let header =
            FileHeader::new(salt, params, content_nonce, filename_nonce, filename_ct).unwrap();
        let serialized = crate::v2::header_ops::serialize(&header);
        let parsed = crate::v2::header_ops::try_deserialize(&serialized).unwrap();

        let (name, _) = decrypt_bytes(
            &parsed.filename_ciphertext,
            &key,
            &parsed.filename_nonce,
            &parsed.binding().aad(AadPurpose::Filename),
        )
        .unwrap();
        let (content, _) = decrypt_bytes(
            &content_ct,
            &key,
            &parsed.content_nonce,
            &parsed.binding().aad(AadPurpose::Content),
        )
        .unwrap();

        assert_eq!(name.as_slice(), b"name.txt");
        assert_eq!(content.as_slice(), b"hello");
    }
}
