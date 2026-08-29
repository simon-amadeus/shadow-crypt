//! Version-erased reading of shadow files.
//!
//! [`ParsedFile`] is the single entry point for reading a shadow file of any
//! format version: it sniffs the version byte, parses with the matching
//! version module, and dispatches every subsequent operation (key derivation,
//! content decryption, filename decryption) to that version's own
//! self-contained implementation. Callers never see which version they are
//! handling unless they ask.
//!
//! This module is the one place that knows about all format versions. It
//! keeps the versions independent of each other: v1 and v2 still share no
//! code — this module sits above both.
//!
//! Key derivation is split out on purpose: [`ParsedFile::kdf_request`]
//! surfaces the header's (untrusted) KDF parameters so the caller can
//! validate and budget them *before* running [`ParsedFile::derive_key`].

use crate::{
    algorithm::Algorithm,
    errors::{FileError, HeaderError, KeyDerivationError},
    file::{FileMetadata, PlaintextFile},
    memory::{SecureBytes, SecureKey, SecureString},
    report::KeyDerivationReport,
    v1, v2, v3,
    version::{Version, read_file_version},
};

/// Upper bound on the serialized header size of any format version.
///
/// Reading this many bytes from the start of a file is always enough to parse
/// its complete header; [`ParsedFile::parse`] tolerates trailing ciphertext
/// bytes, so callers need no version-specific length probing.
pub const MAX_HEADER_LEN: usize = {
    let v1_len = v1::header::FileHeader::min_length();
    let v2_len = v2::header::FileHeader::min_length();
    let v3_len = v3::header::FileHeader::min_length();
    let max12 = if v1_len > v2_len { v1_len } else { v2_len };
    (if max12 > v3_len { max12 } else { v3_len }) + u16::MAX as usize
};

/// The (untrusted) key derivation inputs a file's header asks for,
/// independent of format version.
///
/// These come straight from the file and must be validated against resource
/// bounds before being handed back to [`ParsedFile::derive_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfRequest {
    pub salt: [u8; 16],
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub key_size: u8,
}

/// A parsed shadow file of any format version.
pub struct ParsedFile(Inner);

enum Inner {
    V1(v1::file::EncryptedFile),
    V2(v2::file::EncryptedFile),
    V3(v3::file::EncryptedFile),
}

impl ParsedFile {
    /// Parses a serialized shadow file, dispatching on its version byte.
    ///
    /// Accepts both complete files and header-only prefixes (at least the
    /// full header must be present); trailing bytes are treated as content
    /// ciphertext. When parsing a header-only prefix, use
    /// [`ParsedFile::content_decryptor`] and feed the content bytes
    /// externally — [`ParsedFile::decrypt`] needs the complete file.
    pub fn parse(bytes: &[u8]) -> Result<Self, HeaderError> {
        let inner = match read_file_version(bytes)? {
            Version::V1 => Inner::V1(v1::file::EncryptedFile::from_bytes(bytes)?),
            Version::V2 => Inner::V2(v2::file::EncryptedFile::from_bytes(bytes)?),
            Version::V3 => Inner::V3(v3::file::EncryptedFile::from_bytes(bytes)?),
        };
        Ok(Self(inner))
    }

    pub fn version(&self) -> Version {
        match &self.0 {
            Inner::V1(_) => Version::V1,
            Inner::V2(_) => Version::V2,
            Inner::V3(_) => Version::V3,
        }
    }

    /// The AEAD algorithm this file's format version uses.
    pub fn algorithm(&self) -> Algorithm {
        match &self.0 {
            Inner::V1(_) => v1::ALGORITHM,
            Inner::V2(_) => v2::ALGORITHM,
            Inner::V3(_) => v3::ALGORITHM,
        }
    }

    /// Total length of the file's serialized header; the content ciphertext
    /// starts at this offset.
    pub fn header_length(&self) -> usize {
        match &self.0 {
            Inner::V1(f) => f.header().header_length(),
            Inner::V2(f) => f.header().header_length(),
            Inner::V3(f) => f.header().header_length(),
        }
    }

    /// The key derivation inputs recorded in the file's header. Untrusted:
    /// validate against resource bounds before calling
    /// [`ParsedFile::derive_key`].
    pub fn kdf_request(&self) -> KdfRequest {
        match &self.0 {
            Inner::V1(f) => {
                let p = f.header().kdf_params();
                KdfRequest {
                    salt: *f.header().salt(),
                    memory_cost: p.memory_cost,
                    time_cost: p.time_cost,
                    parallelism: p.parallelism,
                    key_size: p.key_size,
                }
            }
            Inner::V2(f) => {
                let p = f.header().kdf_params();
                KdfRequest {
                    salt: *f.header().salt(),
                    memory_cost: p.memory_cost,
                    time_cost: p.time_cost,
                    parallelism: p.parallelism,
                    key_size: p.key_size,
                }
            }
            Inner::V3(f) => {
                let p = f.header().kdf_params();
                KdfRequest {
                    salt: *f.header().salt(),
                    memory_cost: p.memory_cost,
                    time_cost: p.time_cost,
                    parallelism: p.parallelism,
                    key_size: p.key_size,
                }
            }
        }
    }

    /// Derives the file's encryption key from a password, using the KDF and
    /// parameters of the file's own format version.
    pub fn derive_key(
        &self,
        password: &[u8],
    ) -> Result<(SecureKey, KeyDerivationReport), KeyDerivationError> {
        match &self.0 {
            Inner::V1(f) => f
                .header()
                .kdf_params()
                .derive_key(password, f.header().salt()),
            Inner::V2(f) => f
                .header()
                .kdf_params()
                .derive_key(password, f.header().salt()),
            Inner::V3(f) => f
                .header()
                .kdf_params()
                .derive_key(password, f.header().salt()),
        }
    }

    /// Decrypts the file's filename and content. Requires the file to have
    /// been parsed from its complete bytes; for streamed decryption use
    /// [`ParsedFile::content_decryptor`].
    pub fn decrypt(&self, key: &SecureKey) -> Result<PlaintextFile, FileError> {
        match &self.0 {
            Inner::V1(f) => f.decrypt(key),
            Inner::V2(f) => f.decrypt(key),
            Inner::V3(f) => f.decrypt(key),
        }
    }

    /// Decrypts only the original filename stored in the file's header.
    pub fn decrypt_filename(&self, key: &SecureKey) -> Result<SecureString, FileError> {
        match &self.0 {
            Inner::V1(f) => f.header().decrypt_filename(key),
            Inner::V2(f) => f.header().decrypt_filename(key),
            Inner::V3(f) => Ok(f.header().decrypt_metadata(key)?.filename().clone()),
        }
    }

    /// Decrypts the file's metadata stored in the header. Format versions
    /// that predate metadata storage (v1, v2) return only the filename.
    pub fn decrypt_metadata(&self, key: &SecureKey) -> Result<FileMetadata, FileError> {
        match &self.0 {
            Inner::V1(f) => Ok(FileMetadata::new(
                f.header().decrypt_filename(key)?,
                None,
                None,
            )),
            Inner::V2(f) => Ok(FileMetadata::new(
                f.header().decrypt_filename(key)?,
                None,
                None,
            )),
            Inner::V3(f) => f.header().decrypt_metadata(key),
        }
    }

    /// Starts decrypting the file's content from externally supplied
    /// ciphertext bytes (starting at [`ParsedFile::header_length`]), so the
    /// caller controls I/O and memory. Works uniformly across versions:
    /// [`ContentDecryptor::chunk_len`] says how to feed the bytes.
    pub fn content_decryptor(&self, key: &SecureKey) -> ContentDecryptor<'_> {
        let inner = match &self.0 {
            Inner::V1(f) => DecryptorInner::V1 {
                header: f.header(),
                key: key.clone(),
                done: false,
            },
            Inner::V2(f) => DecryptorInner::V2 {
                header: f.header(),
                key: key.clone(),
                done: false,
            },
            Inner::V3(f) => DecryptorInner::V3(v3::stream::StreamOpener::new(f.header(), key)),
        };
        ContentDecryptor { inner }
    }
}

/// Incremental decryption of one file's content, fed by the caller.
///
/// Formats whose content is a single AEAD message (v1, v2) report
/// [`ContentDecryptor::chunk_len`] `None`: feed the entire content in one
/// [`ContentDecryptor::decrypt_chunk`] call with `is_last = true`. Streaming
/// formats report `Some(n)`: feed `n`-byte pieces, the final one shorter or
/// equal, with `is_last` on the final piece.
pub struct ContentDecryptor<'a> {
    inner: DecryptorInner<'a>,
}

enum DecryptorInner<'a> {
    V1 {
        header: &'a v1::header::FileHeader,
        key: SecureKey,
        done: bool,
    },
    V2 {
        header: &'a v2::header::FileHeader,
        key: SecureKey,
        done: bool,
    },
    V3(v3::stream::StreamOpener),
}

impl ContentDecryptor<'_> {
    /// Ciphertext bytes to feed per [`ContentDecryptor::decrypt_chunk`]
    /// call, or `None` when the whole content must be fed at once.
    pub fn chunk_len(&self) -> Option<usize> {
        match &self.inner {
            DecryptorInner::V1 { .. } | DecryptorInner::V2 { .. } => None,
            DecryptorInner::V3(opener) => Some(opener.chunk_ciphertext_len()),
        }
    }

    /// Decrypts the next piece of content ciphertext. `is_last` marks that
    /// no more bytes follow.
    pub fn decrypt_chunk(
        &mut self,
        ciphertext: &[u8],
        is_last: bool,
    ) -> Result<SecureBytes, FileError> {
        match &mut self.inner {
            DecryptorInner::V1 { header, key, done } => {
                whole_content_chunk(done, is_last)?;
                header.decrypt_content(ciphertext, key)
            }
            DecryptorInner::V2 { header, key, done } => {
                whole_content_chunk(done, is_last)?;
                header.decrypt_content(ciphertext, key)
            }
            DecryptorInner::V3(opener) => opener.open_chunk(ciphertext, is_last),
        }
    }

    /// True once the final piece has been decrypted. A content stream that
    /// ends without this being true was truncated.
    pub fn finished(&self) -> bool {
        match &self.inner {
            DecryptorInner::V1 { done, .. } | DecryptorInner::V2 { done, .. } => *done,
            DecryptorInner::V3(opener) => opener.finished(),
        }
    }
}

/// Guards the single-chunk contract of the whole-content (v1/v2) decryptors.
fn whole_content_chunk(done: &mut bool, is_last: bool) -> Result<(), FileError> {
    if *done || !is_last {
        return Err(FileError::Crypt(
            crate::errors::CryptError::DecryptionError(
                "this format's content must be decrypted as a single final chunk".to_string(),
            ),
        ));
    }
    *done = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal_v3(password: &[u8], filename: &str, content: &[u8]) -> Vec<u8> {
        let salt = [1u8; 16];
        let params = v3::key::KeyDerivationParams::test_defaults();
        let (key, _) = params.derive_key(password, &salt).unwrap();
        let metadata =
            FileMetadata::new(SecureString::new(filename.to_string()), None, Some(0o600));
        v3::file::EncryptedFile::seal(&metadata, content, &key, params, salt, [2u8; 16], [3u8; 24])
            .unwrap()
            .to_bytes()
    }

    fn seal_v2(password: &[u8], filename: &str, content: &[u8]) -> Vec<u8> {
        let salt = [1u8; 16];
        let params = v2::key::KeyDerivationParams::test_defaults();
        let (key, _) = params.derive_key(password, &salt).unwrap();
        let plaintext = PlaintextFile::new(
            SecureString::new(filename.to_string()),
            SecureBytes::new(content.to_vec()),
        );
        v2::file::EncryptedFile::seal(&plaintext, &key, params, salt, [2u8; 24], [3u8; 24])
            .unwrap()
            .to_bytes()
    }

    fn seal_v1(password: &[u8], filename: &str, content: &[u8]) -> Vec<u8> {
        let salt = [1u8; 16];
        let params = v1::key::KeyDerivationParams::test_defaults();
        let content_nonce = [2u8; 24];
        let filename_nonce = [3u8; 24];
        let (key, _) = params.derive_key(password, &salt).unwrap();
        let (filename_ct, _) =
            v1::crypt::encrypt_bytes(filename.as_bytes(), key.as_bytes(), &filename_nonce).unwrap();
        let (content_ct, _) =
            v1::crypt::encrypt_bytes(content, key.as_bytes(), &content_nonce).unwrap();
        let header =
            v1::header::FileHeader::new(salt, params, content_nonce, filename_nonce, filename_ct);
        v1::file::EncryptedFile::new(header, content_ct).to_bytes()
    }

    #[test]
    fn parse_dispatches_on_version_byte() {
        let v1_bytes = seal_v1(b"pw", "a.txt", b"one");
        let v2_bytes = seal_v2(b"pw", "b.txt", b"two");
        let v3_bytes = seal_v3(b"pw", "c.txt", b"three");

        assert_eq!(ParsedFile::parse(&v1_bytes).unwrap().version(), Version::V1);
        assert_eq!(ParsedFile::parse(&v2_bytes).unwrap().version(), Version::V2);
        assert_eq!(ParsedFile::parse(&v3_bytes).unwrap().version(), Version::V3);
    }

    #[test]
    fn parse_rejects_unknown_version() {
        let mut bytes = seal_v2(b"pw", "a.txt", b"x");
        bytes[6] = 99;
        assert!(ParsedFile::parse(&bytes).is_err());
    }

    #[test]
    fn decrypt_round_trips_all_versions() {
        for bytes in [
            seal_v1(b"pw", "name.txt", b"content"),
            seal_v2(b"pw", "name.txt", b"content"),
            seal_v3(b"pw", "name.txt", b"content"),
        ] {
            let parsed = ParsedFile::parse(&bytes).unwrap();
            let (key, _) = parsed.derive_key(b"pw").unwrap();
            let plaintext = parsed.decrypt(&key).unwrap();
            assert_eq!(plaintext.filename().as_str(), "name.txt");
            assert_eq!(plaintext.content().as_slice(), b"content");
        }
    }

    #[test]
    fn decrypt_filename_works_on_header_only_prefix() {
        for bytes in [
            seal_v1(b"pw", "name.txt", b"content"),
            seal_v2(b"pw", "name.txt", b"content"),
            seal_v3(b"pw", "name.txt", b"content"),
        ] {
            // Simulate a bounded header read: any prefix at least as long as
            // the header (here capped at MAX_HEADER_LEN) must be parseable.
            let prefix = &bytes[..bytes.len().min(MAX_HEADER_LEN)];
            let parsed = ParsedFile::parse(prefix).unwrap();
            let (key, _) = parsed.derive_key(b"pw").unwrap();
            assert_eq!(parsed.decrypt_filename(&key).unwrap().as_str(), "name.txt");
        }
    }

    /// The caller-fed decryptor must reproduce the content for every version
    /// when fed according to its own chunk_len contract.
    #[test]
    fn content_decryptor_round_trips_all_versions() {
        for bytes in [
            seal_v1(b"pw", "name.txt", b"content"),
            seal_v2(b"pw", "name.txt", b"content"),
            seal_v3(b"pw", "name.txt", b"content"),
        ] {
            let parsed = ParsedFile::parse(&bytes).unwrap();
            let (key, _) = parsed.derive_key(b"pw").unwrap();
            let content_bytes = &bytes[parsed.header_length()..];

            let mut decryptor = parsed.content_decryptor(&key);
            let mut out = Vec::new();
            match decryptor.chunk_len() {
                None => {
                    out.extend_from_slice(
                        decryptor
                            .decrypt_chunk(content_bytes, true)
                            .unwrap()
                            .as_slice(),
                    );
                }
                Some(n) => {
                    let pieces: Vec<&[u8]> = content_bytes.chunks(n).collect();
                    for (i, piece) in pieces.iter().enumerate() {
                        out.extend_from_slice(
                            decryptor
                                .decrypt_chunk(piece, i == pieces.len() - 1)
                                .unwrap()
                                .as_slice(),
                        );
                    }
                }
            }

            assert!(decryptor.finished());
            assert_eq!(out, b"content");
        }
    }

    #[test]
    fn decrypt_metadata_reports_fields_by_version() {
        let v2_bytes = seal_v2(b"pw", "name.txt", b"content");
        let parsed = ParsedFile::parse(&v2_bytes).unwrap();
        let (key, _) = parsed.derive_key(b"pw").unwrap();
        let meta = parsed.decrypt_metadata(&key).unwrap();
        assert_eq!(meta.filename().as_str(), "name.txt");
        assert_eq!(meta.mode(), None);

        let v3_bytes = seal_v3(b"pw", "name.txt", b"content");
        let parsed = ParsedFile::parse(&v3_bytes).unwrap();
        let (key, _) = parsed.derive_key(b"pw").unwrap();
        let meta = parsed.decrypt_metadata(&key).unwrap();
        assert_eq!(meta.filename().as_str(), "name.txt");
        assert_eq!(meta.mode(), Some(0o600));
    }

    #[test]
    fn kdf_request_reflects_header_params() {
        let bytes = seal_v2(b"pw", "a.txt", b"x");
        let parsed = ParsedFile::parse(&bytes).unwrap();
        let req = parsed.kdf_request();

        let expected = v2::key::KeyDerivationParams::test_defaults();
        assert_eq!(req.salt, [1u8; 16]);
        assert_eq!(req.memory_cost, expected.memory_cost);
        assert_eq!(req.time_cost, expected.time_cost);
        assert_eq!(req.parallelism, expected.parallelism);
        assert_eq!(req.key_size, expected.key_size);
    }
}
