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
            let header = FileHeader::new(salt, params.clone(), content_nonce, filename_nonce, filename_ct.clone());
            let serialized = header.serialize();
            prop_assert_eq!(&serialized[0..6], b"SHADOW");
            prop_assert_eq!(serialized[6], 1);

            let parsed = FileHeader::try_deserialize(&serialized).unwrap();
            prop_assert_eq!(parsed.salt(), &salt);
            prop_assert_eq!(parsed.kdf_params(), &params);
            prop_assert_eq!(parsed.content_nonce(), &content_nonce);
            prop_assert_eq!(parsed.filename_nonce(), &filename_nonce);
            prop_assert_eq!(parsed.filename_ciphertext(), filename_ct.as_slice());
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
            let header = FileHeader::new(salt, params.clone(), content_nonce, filename_nonce, filename_ct.clone()).unwrap();
            let serialized = header.serialize();
            prop_assert_eq!(&serialized[0..6], b"SHADOW");
            prop_assert_eq!(serialized[6], 2);

            let parsed = FileHeader::try_deserialize(&serialized).unwrap();
            prop_assert_eq!(parsed.salt(), &salt);
            prop_assert_eq!(parsed.kdf_params(), &params);
            prop_assert_eq!(parsed.content_nonce(), &content_nonce);
            prop_assert_eq!(parsed.filename_nonce(), &filename_nonce);
            prop_assert_eq!(parsed.filename_ciphertext(), filename_ct.as_slice());
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

mod v3_props {
    use super::*;
    use shadow_crypt_core::{
        file::FileMetadata,
        memory::{SecureKey, SecureString},
        v3::{file::EncryptedFile, header::FileHeader, key::KeyDerivationParams, metadata},
    };

    fn arbitrary_metadata() -> impl Strategy<Value = FileMetadata> {
        (
            "[a-zA-Z0-9 ._\\-\u{e0}-\u{ff}]{0,64}",
            proptest::option::of((0i64..=4_102_444_800i64, 0u32..1_000_000_000)),
            proptest::option::of(any::<u32>()),
        )
            .prop_map(|(name, mtime, mode)| {
                let mtime = mtime.map(|(secs, nanos)| {
                    std::time::UNIX_EPOCH + std::time::Duration::new(secs as u64, nanos)
                });
                FileMetadata::new(SecureString::new(name), mtime, mode)
            })
    }

    proptest! {
        #[test]
        fn header_round_trips(
            salt in any::<[u8; 16]>(),
            memory_cost in any::<u32>(),
            time_cost in any::<u32>(),
            parallelism in any::<u32>(),
            key_size in any::<u8>(),
            nonce_prefix in any::<[u8; 16]>(),
            chunk_size in 1u32..=1024 * 1024,
            metadata_nonce in any::<[u8; 24]>(),
            metadata_ct in proptest::collection::vec(any::<u8>(), 0..MAX_FILENAME_CT),
        ) {
            let params = KeyDerivationParams::new(memory_cost, time_cost, parallelism, key_size);
            let header = FileHeader::new(
                salt, params.clone(), nonce_prefix, chunk_size, metadata_nonce, metadata_ct.clone(),
            ).unwrap();
            let serialized = header.serialize();
            prop_assert_eq!(&serialized[0..6], b"SHADOW");
            prop_assert_eq!(serialized[6], 3);

            let parsed = FileHeader::try_deserialize(&serialized).unwrap();
            prop_assert_eq!(parsed.salt(), &salt);
            prop_assert_eq!(parsed.kdf_params(), &params);
            prop_assert_eq!(parsed.nonce_prefix(), &nonce_prefix);
            prop_assert_eq!(parsed.chunk_size(), chunk_size);
            prop_assert_eq!(parsed.metadata_nonce(), &metadata_nonce);
            prop_assert_eq!(parsed.metadata_ciphertext(), metadata_ct.as_slice());
        }

        #[test]
        fn try_deserialize_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = FileHeader::try_deserialize(&bytes);
        }

        #[test]
        fn metadata_envelope_round_trips(meta in arbitrary_metadata()) {
            let parsed = metadata::parse(metadata::serialize(&meta).unwrap().as_slice()).unwrap();
            prop_assert_eq!(parsed.filename().as_str(), meta.filename().as_str());
            prop_assert_eq!(parsed.mtime(), meta.mtime());
            prop_assert_eq!(parsed.mode(), meta.mode());
        }

        #[test]
        fn metadata_parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = metadata::parse(&bytes);
        }

        /// Whole-file round trip across arbitrary content sizes, exercising
        /// the chunking including exact-multiple and empty edge cases.
        #[test]
        fn seal_decrypt_round_trips(
            key_bytes in any::<[u8; 32]>(),
            content in proptest::collection::vec(any::<u8>(), 0..2048),
            meta in arbitrary_metadata(),
        ) {
            let key = SecureKey::new(key_bytes);
            let sealed = EncryptedFile::seal(
                &meta, &content, &key,
                KeyDerivationParams::new(1024, 1, 1, 32),
                [1u8; 16], [2u8; 16], [3u8; 24],
            ).unwrap();

            let parsed = EncryptedFile::from_bytes(&sealed.to_bytes()).unwrap();
            let decrypted = parsed.decrypt(&key).unwrap();
            prop_assert_eq!(decrypted.filename().as_str(), meta.filename().as_str());
            prop_assert_eq!(decrypted.content().as_slice(), content.as_slice());
        }

        /// Corrupting any single byte of a serialized v3 file must make
        /// decryption fail: header corruption breaks parsing or the AAD
        /// binding, chunk corruption breaks that chunk's tag.
        #[test]
        fn single_byte_corruption_is_detected(
            key_bytes in any::<[u8; 32]>(),
            content in proptest::collection::vec(any::<u8>(), 0..512),
            flip_index in any::<prop::sample::Index>(),
            flip_bit in 0u8..8,
        ) {
            let key = SecureKey::new(key_bytes);
            let meta = FileMetadata::new(
                SecureString::new("name.txt".to_string()), None, Some(0o644),
            );
            let sealed = EncryptedFile::seal(
                &meta, &content, &key,
                KeyDerivationParams::new(1024, 1, 1, 32),
                [1u8; 16], [2u8; 16], [3u8; 24],
            ).unwrap();

            let mut bytes = sealed.to_bytes();
            let index = flip_index.index(bytes.len());
            bytes[index] ^= 1 << flip_bit;

            let decrypted = EncryptedFile::from_bytes(&bytes)
                .map_err(|_| ())
                .and_then(|parsed| parsed.decrypt(&key).map_err(|_| ()));
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
            prop_assert_eq!(result.is_ok(), matches!(version_byte, 1..=3));
        }
    }
}
