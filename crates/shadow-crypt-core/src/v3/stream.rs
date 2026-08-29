//! Chunked (streaming) content encryption for the v3 format.
//!
//! The content is a sequence of AEAD chunks of `chunk_size` plaintext bytes
//! (the final chunk may be shorter, including empty). Each chunk's 24-byte
//! nonce is `nonce_prefix (16) || counter (7, little endian) || final flag
//! (1)`, and every chunk authenticates the header binding under the content
//! domain. The counter makes reordering fail authentication, and the final
//! flag makes truncation at a chunk boundary fail: the last present chunk
//! was not sealed as final, so opening it as final does not authenticate.
//!
//! An empty file is one final chunk with empty plaintext, so every content
//! stream contains at least one chunk.

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};

use crate::{
    errors::{CryptError, FileError},
    file::FileMetadata,
    memory::{SecureBytes, SecureKey},
    v3::{
        crypt,
        header::{AadPurpose, FileHeader, HeaderBinding},
        key::KeyDerivationParams,
    },
};

/// Plaintext bytes per chunk written by this implementation. Reading accepts
/// any chunk size the header declares, within the parse-time bound.
pub const CHUNK_SIZE: u32 = 1024 * 1024; // 1 MiB

/// AEAD authentication tag length appended to every chunk.
pub const TAG_SIZE: usize = 16;

/// Highest chunk counter value that fits the 7-byte nonce field.
const MAX_COUNTER: u64 = (1 << 56) - 1;

fn chunk_nonce(prefix: &[u8; 16], counter: u64, is_last: bool) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(prefix);
    nonce[16..23].copy_from_slice(&counter.to_le_bytes()[..7]);
    nonce[23] = u8::from(is_last);
    nonce
}

/// Incremental encryption of one file's content stream.
pub struct StreamSealer {
    cipher: XChaCha20Poly1305,
    nonce_prefix: [u8; 16],
    chunk_size: usize,
    aad: Vec<u8>,
    counter: u64,
    finished: bool,
}

impl StreamSealer {
    /// Starts sealing a new v3 file: encrypts the metadata envelope, builds
    /// the header, and returns it together with the sealer for the content
    /// chunks. The caller supplies the derived key and fresh random
    /// salt/nonces, keeping this deterministic.
    pub fn begin(
        metadata: &FileMetadata,
        key: &SecureKey,
        kdf_params: KeyDerivationParams,
        salt: [u8; 16],
        nonce_prefix: [u8; 16],
        metadata_nonce: [u8; 24],
    ) -> Result<(FileHeader, StreamSealer), FileError> {
        Self::begin_with_chunk_size(
            metadata,
            key,
            kdf_params,
            salt,
            nonce_prefix,
            metadata_nonce,
            CHUNK_SIZE,
        )
    }

    /// [`StreamSealer::begin`] with an explicit chunk size, for callers with
    /// unusual chunking needs. The size must satisfy the same bounds the
    /// header enforces.
    pub fn begin_with_chunk_size(
        metadata: &FileMetadata,
        key: &SecureKey,
        kdf_params: KeyDerivationParams,
        salt: [u8; 16],
        nonce_prefix: [u8; 16],
        metadata_nonce: [u8; 24],
        chunk_size: u32,
    ) -> Result<(FileHeader, StreamSealer), FileError> {
        let envelope = crate::v3::metadata::serialize(metadata)?;

        let binding = HeaderBinding::new(
            &salt,
            &kdf_params,
            &nonce_prefix,
            chunk_size,
            &metadata_nonce,
        );
        let (metadata_ciphertext, _) = crypt::encrypt_bytes(
            envelope.as_slice(),
            key.as_bytes(),
            &metadata_nonce,
            &binding.aad(AadPurpose::Metadata),
        )?;
        let content_aad = binding.aad(AadPurpose::Content);

        let header = FileHeader::new(
            salt,
            kdf_params,
            nonce_prefix,
            chunk_size,
            metadata_nonce,
            metadata_ciphertext,
        )?;

        let sealer = StreamSealer {
            cipher: XChaCha20Poly1305::new(key.as_bytes().into()),
            nonce_prefix,
            chunk_size: chunk_size as usize,
            aad: content_aad,
            counter: 0,
            finished: false,
        };
        Ok((header, sealer))
    }

    /// Plaintext bytes to feed per [`StreamSealer::seal_chunk`] call; only
    /// the final chunk may be shorter.
    pub fn chunk_plaintext_len(&self) -> usize {
        self.chunk_size
    }

    /// Seals the next chunk. Every chunk except the last must be exactly
    /// `chunk_plaintext_len` bytes; the last may be shorter (or empty).
    pub fn seal_chunk(&mut self, plaintext: &[u8], is_last: bool) -> Result<Vec<u8>, FileError> {
        if self.finished {
            return Err(stream_error("chunk sealed after the final chunk"));
        }
        if !is_last && plaintext.len() != self.chunk_size {
            return Err(stream_error("non-final chunk must be exactly chunk-sized"));
        }
        if plaintext.len() > self.chunk_size {
            return Err(stream_error("chunk larger than the declared chunk size"));
        }
        if self.counter > MAX_COUNTER {
            return Err(stream_error("chunk counter overflow"));
        }

        let nonce = chunk_nonce(&self.nonce_prefix, self.counter, is_last);
        let ciphertext = self
            .cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: &self.aad,
                },
            )
            .map_err(|e| {
                FileError::Crypt(CryptError::EncryptionError(format!(
                    "Encryption failed: {}",
                    e
                )))
            })?;

        self.counter += 1;
        self.finished = is_last;
        Ok(ciphertext)
    }

    /// True once the final chunk has been sealed.
    pub fn finished(&self) -> bool {
        self.finished
    }
}

/// Incremental decryption of one file's content stream.
pub struct StreamOpener {
    cipher: XChaCha20Poly1305,
    nonce_prefix: [u8; 16],
    chunk_size: usize,
    aad: Vec<u8>,
    counter: u64,
    finished: bool,
}

impl StreamOpener {
    pub fn new(header: &FileHeader, key: &SecureKey) -> StreamOpener {
        StreamOpener {
            cipher: XChaCha20Poly1305::new(key.as_bytes().into()),
            nonce_prefix: *header.nonce_prefix(),
            chunk_size: header.chunk_size() as usize,
            aad: header.binding().aad(AadPurpose::Content),
            counter: 0,
            finished: false,
        }
    }

    /// Ciphertext bytes to feed per [`StreamOpener::open_chunk`] call; only
    /// the final chunk may be shorter.
    pub fn chunk_ciphertext_len(&self) -> usize {
        self.chunk_size + TAG_SIZE
    }

    /// Opens the next chunk. `is_last` marks that no more ciphertext
    /// follows; sealing and opening must agree on which chunk is final or
    /// authentication fails (this is what detects truncation).
    pub fn open_chunk(
        &mut self,
        ciphertext: &[u8],
        is_last: bool,
    ) -> Result<SecureBytes, FileError> {
        if self.finished {
            return Err(stream_error("data present after the final chunk"));
        }
        if !is_last && ciphertext.len() != self.chunk_ciphertext_len() {
            return Err(stream_error("non-final chunk has the wrong length"));
        }
        if ciphertext.len() < TAG_SIZE || ciphertext.len() > self.chunk_ciphertext_len() {
            return Err(stream_error("chunk has an impossible length"));
        }
        if self.counter > MAX_COUNTER {
            return Err(stream_error("chunk counter overflow"));
        }

        let nonce = chunk_nonce(&self.nonce_prefix, self.counter, is_last);
        let plaintext = self
            .cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: ciphertext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| {
                FileError::Crypt(CryptError::DecryptionError(
                    "authentication failed (wrong password, or the file is corrupted)".to_string(),
                ))
            })?;

        self.counter += 1;
        self.finished = is_last;
        Ok(SecureBytes::new(plaintext))
    }

    /// True once the final chunk has been opened. A stream that ends without
    /// this being true was truncated.
    pub fn finished(&self) -> bool {
        self.finished
    }
}

fn stream_error(msg: &str) -> FileError {
    FileError::Crypt(CryptError::DecryptionError(format!(
        "invalid content stream: {}",
        msg
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::SecureString;

    fn test_setup(chunk_size: u32) -> (FileHeader, StreamSealer, SecureKey) {
        let key = SecureKey::new([9u8; 32]);
        let metadata = FileMetadata::new(SecureString::new("a.txt".to_string()), None, None);
        let (header, sealer) = StreamSealer::begin_with_chunk_size(
            &metadata,
            &key,
            KeyDerivationParams::test_defaults(),
            [1u8; 16],
            [2u8; 16],
            [3u8; 24],
            chunk_size,
        )
        .unwrap();
        (header, sealer, key)
    }

    /// Chunks like the shell's reader: fixed-size pieces, the last piece is
    /// final (a full-sized final piece on exact multiples, one empty piece
    /// for empty content).
    fn seal_all(sealer: &mut StreamSealer, content: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
        let pieces: Vec<&[u8]> = if content.is_empty() {
            vec![&[][..]]
        } else {
            content.chunks(chunk_size).collect()
        };
        pieces
            .iter()
            .enumerate()
            .map(|(i, piece)| sealer.seal_chunk(piece, i == pieces.len() - 1).unwrap())
            .collect()
    }

    fn open_all(
        header: &FileHeader,
        key: &SecureKey,
        chunks: &[Vec<u8>],
    ) -> Result<Vec<u8>, FileError> {
        let mut opener = StreamOpener::new(header, key);
        let mut out = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let is_last = i == chunks.len() - 1;
            out.extend_from_slice(opener.open_chunk(chunk, is_last)?.as_slice());
        }
        assert!(opener.finished());
        Ok(out)
    }

    #[test]
    fn multi_chunk_round_trip() {
        let (header, mut sealer, key) = test_setup(8);
        let content = b"this content spans multiple chunks".to_vec();

        let chunks = seal_all(&mut sealer, &content, 8);
        assert!(chunks.len() > 2);
        assert_eq!(open_all(&header, &key, &chunks).unwrap(), content);
    }

    #[test]
    fn empty_content_round_trip() {
        let (header, mut sealer, key) = test_setup(8);
        let chunks = seal_all(&mut sealer, b"", 8);
        assert_eq!(chunks.len(), 1);
        assert_eq!(open_all(&header, &key, &chunks).unwrap(), b"");
    }

    #[test]
    fn exact_multiple_round_trip() {
        let (header, mut sealer, key) = test_setup(8);
        let content = b"0123456789abcdef".to_vec(); // exactly two chunks

        let chunks = seal_all(&mut sealer, &content, 8);
        assert_eq!(chunks.len(), 2); // the final chunk is full-sized
        assert_eq!(open_all(&header, &key, &chunks).unwrap(), content);
    }

    #[test]
    fn truncation_is_detected() {
        let (header, mut sealer, key) = test_setup(8);
        let mut chunks = seal_all(&mut sealer, b"0123456789abcdefgh", 8);

        // Drop the final chunk: the new last chunk was not sealed as final.
        chunks.pop();
        assert!(open_all(&header, &key, &chunks).is_err());
    }

    #[test]
    fn reordering_is_detected() {
        let (header, mut sealer, key) = test_setup(8);
        let mut chunks = seal_all(&mut sealer, b"0123456789abcdefgh", 8);
        chunks.swap(0, 1);
        assert!(open_all(&header, &key, &chunks).is_err());
    }

    #[test]
    fn corruption_is_detected() {
        let (header, mut sealer, key) = test_setup(8);
        let mut chunks = seal_all(&mut sealer, b"0123456789abcdefgh", 8);
        chunks[1][0] ^= 1;
        assert!(open_all(&header, &key, &chunks).is_err());
    }

    #[test]
    fn sealing_after_final_chunk_fails() {
        let (_, mut sealer, _) = test_setup(8);
        sealer.seal_chunk(b"tail", true).unwrap();
        assert!(sealer.seal_chunk(b"more", true).is_err());
    }

    #[test]
    fn short_non_final_chunk_fails() {
        let (_, mut sealer, _) = test_setup(8);
        assert!(sealer.seal_chunk(b"tiny", false).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let (header, mut sealer, key) = test_setup(8);
        let chunks = seal_all(&mut sealer, b"content", 8);

        let wrong = SecureKey::new([1u8; 32]);
        assert!(open_all(&header, &wrong, &chunks).is_err());
        assert!(open_all(&header, &key, &chunks).is_ok());
    }
}
