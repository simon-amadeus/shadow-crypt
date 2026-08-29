//! Property-based tests for the file formats and AEAD primitives.
//!
//! These check invariants that unit tests with hand-picked values cannot:
//! headers round-trip for *any* field values, deserialization never panics on
//! *any* byte soup, and v2's domain separation holds for *any* inputs.

use proptest::prelude::*;
use shadow_crypt_core::{v1, v2, version};

/// Filename ciphertexts up to a few KiB; the length field allows up to
/// u16::MAX but large vectors only slow the tests without adding coverage.
const MAX_FILENAME_CT: usize = 2048;

mod v1_props {
    use super::*;
    use v1::{header::FileHeader, key::KeyDerivationParams};

    proptest! {
        #[test]
        fn header_round_trips(
            salt in any::<[u8; 16]>(),
            memory_cost in any::<u32>(),
            time_cost in any::<u32>(),
            parallelism in any::<u32>(),
            key_size in any::<u8>(),
            content_nonce in any::<[u8; 24]>(),
            filename_nonce in any::<[u8; 24]>(),
            filename_ct in proptest::collection::vec(any::<u8>(), 0..MAX_FILENAME_CT),
        ) {
            let params = KeyDerivationParams::new(memory_cost, time_cost, parallelism, key_size);
            let header = FileHeader::new(salt, params, content_nonce, filename_nonce, filename_ct.clone());
            let parsed = FileHeader::try_deserialize(&header.serialize()).unwrap();

            prop_assert_eq!(parsed.salt, salt);
            prop_assert_eq!(parsed.kdf_memory, memory_cost);
            prop_assert_eq!(parsed.kdf_iterations, time_cost);
            prop_assert_eq!(parsed.kdf_parallelism, parallelism);
            prop_assert_eq!(parsed.kdf_key_length, key_size);
            prop_assert_eq!(parsed.content_nonce, content_nonce);
            prop_assert_eq!(parsed.filename_nonce, filename_nonce);
            prop_assert_eq!(parsed.filename_ciphertext, filename_ct);
        }

        #[test]
        fn try_deserialize_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = FileHeader::try_deserialize(&bytes);
        }

        #[test]
        fn encrypt_decrypt_round_trips(
            plaintext in proptest::collection::vec(any::<u8>(), 0..512),
            key in any::<[u8; 32]>(),
            nonce in any::<[u8; 24]>(),
        ) {
            let (ciphertext, _) = v1::crypt::encrypt_bytes(&plaintext, &key, &nonce).unwrap();
            let (decrypted, _) = v1::crypt::decrypt_bytes(&ciphertext, &key, &nonce).unwrap();
            prop_assert_eq!(decrypted.as_slice(), plaintext.as_slice());
        }

        #[test]
        fn decrypt_never_panics_on_garbage(
            ciphertext in proptest::collection::vec(any::<u8>(), 0..512),
            key in any::<[u8; 32]>(),
            nonce in any::<[u8; 24]>(),
        ) {
            let _ = v1::crypt::decrypt_bytes(&ciphertext, &key, &nonce);
        }
    }
}

mod v2_props {
    use super::*;
    use shadow_crypt_core::memory::SecureKey;
    use v2::{
        file::EncryptedFile,
        header::{AadPurpose, FileHeader, HeaderBinding},
        key::KeyDerivationParams,
    };

    proptest! {
        #[test]
        fn header_round_trips(
            salt in any::<[u8; 16]>(),
            memory_cost in any::<u32>(),
            time_cost in any::<u32>(),
            parallelism in any::<u32>(),
            key_size in any::<u8>(),
            content_nonce in any::<[u8; 24]>(),
            filename_nonce in any::<[u8; 24]>(),
            filename_ct in proptest::collection::vec(any::<u8>(), 0..MAX_FILENAME_CT),
        ) {
            let params = KeyDerivationParams::new(memory_cost, time_cost, parallelism, key_size);
            let header = FileHeader::new(salt, params, content_nonce, filename_nonce, filename_ct.clone()).unwrap();
            let parsed = FileHeader::try_deserialize(&header.serialize()).unwrap();

            prop_assert_eq!(parsed.version, 2);
            prop_assert_eq!(parsed.salt, salt);
            prop_assert_eq!(parsed.kdf_memory, memory_cost);
            prop_assert_eq!(parsed.kdf_iterations, time_cost);
            prop_assert_eq!(parsed.kdf_parallelism, parallelism);
            prop_assert_eq!(parsed.kdf_key_length, key_size);
            prop_assert_eq!(parsed.content_nonce, content_nonce);
            prop_assert_eq!(parsed.filename_nonce, filename_nonce);
            prop_assert_eq!(parsed.filename_ciphertext, filename_ct);
        }

        #[test]
        fn try_deserialize_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = FileHeader::try_deserialize(&bytes);
        }

        #[test]
        fn encrypt_decrypt_round_trips_with_aad(
            plaintext in proptest::collection::vec(any::<u8>(), 0..512),
            key in any::<[u8; 32]>(),
            nonce in any::<[u8; 24]>(),
            aad in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let (ciphertext, _) = v2::crypt::encrypt_bytes(&plaintext, &key, &nonce, &aad).unwrap();
            let (decrypted, _) = v2::crypt::decrypt_bytes(&ciphertext, &key, &nonce, &aad).unwrap();
            prop_assert_eq!(decrypted.as_slice(), plaintext.as_slice());
        }

        #[test]
        fn different_aad_always_fails(
            plaintext in proptest::collection::vec(any::<u8>(), 0..512),
            key in any::<[u8; 32]>(),
            nonce in any::<[u8; 24]>(),
            aad1 in proptest::collection::vec(any::<u8>(), 0..128),
            aad2 in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            prop_assume!(aad1 != aad2);
            let (ciphertext, _) = v2::crypt::encrypt_bytes(&plaintext, &key, &nonce, &aad1).unwrap();
            prop_assert!(v2::crypt::decrypt_bytes(&ciphertext, &key, &nonce, &aad2).is_err());
        }

        /// The swap-attack invariant: for any key, nonces, and header fields,
        /// a ciphertext produced under the filename domain never authenticates
        /// under the content domain (and vice versa), even when everything
        /// else matches.
        #[test]
        fn purpose_domains_never_cross_authenticate(
            plaintext in proptest::collection::vec(any::<u8>(), 0..256),
            key in any::<[u8; 32]>(),
            salt in any::<[u8; 16]>(),
            memory_cost in any::<u32>(),
            time_cost in any::<u32>(),
            parallelism in any::<u32>(),
            key_size in any::<u8>(),
            content_nonce in any::<[u8; 24]>(),
            filename_nonce in any::<[u8; 24]>(),
        ) {
            let params = KeyDerivationParams::new(memory_cost, time_cost, parallelism, key_size);
            let binding = HeaderBinding::new(&salt, &params, &content_nonce, &filename_nonce);

            let (as_filename, _) = v2::crypt::encrypt_bytes(
                &plaintext, &key, &filename_nonce, &binding.aad(AadPurpose::Filename),
            ).unwrap();
            prop_assert!(v2::crypt::decrypt_bytes(
                &as_filename, &key, &filename_nonce, &binding.aad(AadPurpose::Content),
            ).is_err());

            let (as_content, _) = v2::crypt::encrypt_bytes(
                &plaintext, &key, &content_nonce, &binding.aad(AadPurpose::Content),
            ).unwrap();
            prop_assert!(v2::crypt::decrypt_bytes(
                &as_content, &key, &content_nonce, &binding.aad(AadPurpose::Filename),
            ).is_err());
        }

        /// Corrupting any single byte of a serialized v2 file (header or
        /// content ciphertext) must make decryption of the touched part fail:
        /// header corruption breaks parsing or the AAD binding, ciphertext
        /// corruption breaks the AEAD tag.
        #[test]
        fn single_byte_corruption_is_detected(
            key in any::<[u8; 32]>(),
            salt in any::<[u8; 16]>(),
            content_nonce in any::<[u8; 24]>(),
            filename_nonce in any::<[u8; 24]>(),
            flip_index in any::<prop::sample::Index>(),
            flip_bit in 0u8..8,
        ) {
            let params = KeyDerivationParams::new(1024, 1, 1, 32);
            let binding = HeaderBinding::new(&salt, &params, &content_nonce, &filename_nonce);

            let (filename_ct, _) = v2::crypt::encrypt_bytes(
                b"name.txt", &key, &filename_nonce, &binding.aad(AadPurpose::Filename),
            ).unwrap();
            let (content_ct, _) = v2::crypt::encrypt_bytes(
                b"content", &key, &content_nonce, &binding.aad(AadPurpose::Content),
            ).unwrap();
            let header = FileHeader::new(
                salt, params, content_nonce, filename_nonce, filename_ct,
            ).unwrap();

            let mut bytes = header.serialize();
            bytes.extend_from_slice(&content_ct);

            let index = flip_index.index(bytes.len());
            bytes[index] ^= 1 << flip_bit;

            // Whatever was corrupted, the file must not decrypt cleanly end
            // to end with the original semantics.
            let decrypted = EncryptedFile::from_bytes(&bytes)
                .map_err(|_| ())
                .and_then(|parsed| parsed.decrypt(&SecureKey::new(key)).map_err(|_| ()));

            prop_assert!(decrypted.is_err());
        }
    }
}

mod version_props {
    use super::*;

    proptest! {
        #[test]
        fn read_file_version_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = version::read_file_version(&bytes);
        }

        #[test]
        fn read_file_version_accepts_only_known_versions(version_byte in any::<u8>()) {
            let mut bytes = b"SHADOW".to_vec();
            bytes.push(version_byte);
            let result = version::read_file_version(&bytes);
            prop_assert_eq!(result.is_ok(), matches!(version_byte, 1 | 2));
        }
    }
}
