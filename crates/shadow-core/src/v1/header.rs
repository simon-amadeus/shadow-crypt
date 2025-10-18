use std::mem;

use crate::v1::key::KeyDerivationParams;

/// Complete v1 file header
#[derive(Debug, Clone)]
pub struct FileHeader {
    pub magic: ShadowMagic,                    // 6 bytes: "SHADOW"
    pub version: FileVersion,                  // 2 bytes: Version (fixed to 1)
    pub size: HeaderSize,                      // 4 bytes: Total header size
    pub salt: Argon2idSalt,                    // 16 bytes: Salt for key derivation
    pub params: KeyDerivationParams,           // Argon2id parameters for key derivation
    pub content_nonce: XChaCha20Nonce,         // 24 bytes: Nonce for content encryption
    pub content_tag: Poly1305Tag,              // 16 bytes: Authentication tag for content
    pub encrypted_filename: EncryptedFileName, // Variable size: Encrypted filename
}

impl FileHeader {
    pub fn new(
        salt: Argon2idSalt,
        params: KeyDerivationParams,
        content_nonce: XChaCha20Nonce,
        content_tag: Poly1305Tag,
        encrypted_filename: EncryptedFileName,
    ) -> Self {
        let calc_size = Argon2idSalt::size()
            + KeyDerivationParams::size()
            + XChaCha20Nonce::size()
            + Poly1305Tag::size()
            + encrypted_filename.size()
            + ShadowMagic::size()
            + FileVersion::size();
        let size = HeaderSize(calc_size as u32);
        Self {
            magic: ShadowMagic,
            version: FileVersion,
            size,
            salt,
            params,
            content_nonce,
            content_tag,
            encrypted_filename,
        }
    }

    // Returns length of all fixed-size fields in the header
    // This only excludes the variable-size filename ciphertext
    pub fn min_size() -> usize {
        ShadowMagic::size()
            + FileVersion::size()
            + Argon2idSalt::size()
            + KeyDerivationParams::size()
            + XChaCha20Nonce::size()
            + Poly1305Tag::size()
            + EncryptedFileName::min_size()
    }

    pub fn size(&self) -> usize {
        ShadowMagic::size()
            + FileVersion::size()
            + Argon2idSalt::size()
            + XChaCha20Nonce::size()
            + Poly1305Tag::size()
            + self.encrypted_filename.size()
    }
}

/// Encrypted filename with nonce and authentication tag
#[derive(Debug, Clone)]
pub struct EncryptedFileName {
    nonce: XChaCha20Nonce, // Nonce for filename encryption
    tag: Poly1305Tag,      // Authentication tag for filename
    ciphertext_size: u16,  // Size of encrypted filename
    ciphertext: Vec<u8>,   // Encrypted filename
}

impl EncryptedFileName {
    pub fn new(nonce: XChaCha20Nonce, tag: Poly1305Tag, ciphertext: Vec<u8>) -> Self {
        Self {
            nonce,
            tag,
            ciphertext_size: ciphertext.len() as u16,
            ciphertext,
        }
    }
    pub fn get_offset_to_ciphertext_size() -> usize {
        XChaCha20Nonce::size() + Poly1305Tag::size()
    }
    pub fn min_size() -> usize {
        XChaCha20Nonce::size() + Poly1305Tag::size() + mem::size_of::<u16>()
    }
    pub fn size(&self) -> usize {
        EncryptedFileName::min_size() + self.ciphertext.len()
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(self.nonce.as_bytes());
        output.extend_from_slice(self.tag.as_bytes());
        output.extend_from_slice(&self.ciphertext_size.to_le_bytes());
        output.extend_from_slice(&self.ciphertext);
        output
    }
}

/// Magic bytes to identify the v1 file format
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowMagic;
impl ShadowMagic {
    pub const BYTES: [u8; 6] = *b"SHADOW";
    pub fn size() -> usize {
        Self::BYTES.len()
    }
}

/// File format version, fixed to 1 for this implementation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileVersion;
impl FileVersion {
    pub const VALUE: u16 = 1;
    pub fn as_u16() -> u16 {
        Self::VALUE
    }
    pub fn size() -> usize {
        mem::size_of::<u16>()
    }
}

/// Salt for Argon2id key derivation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argon2idSalt([u8; 16]);
impl Argon2idSalt {
    pub fn new(salt: [u8; 16]) -> Self {
        Self(salt)
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
    pub fn size() -> usize {
        mem::size_of::<[u8; 16]>()
    }
}

/// Nonce for XChaCha20-Poly1305 encryption
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XChaCha20Nonce([u8; 24]);
impl XChaCha20Nonce {
    pub fn new(nonce: [u8; 24]) -> Self {
        Self(nonce)
    }
    pub fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }
    pub fn size() -> usize {
        mem::size_of::<[u8; 24]>()
    }
}

/// Authentication tag for XChaCha20-Poly1305
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Poly1305Tag([u8; 16]);
impl Poly1305Tag {
    pub fn new(tag: [u8; 16]) -> Self {
        Self(tag)
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
    pub fn size() -> usize {
        mem::size_of::<[u8; 16]>()
    }
}

/// Total header size in bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderSize(pub u32);
impl HeaderSize {
    pub fn get(&self) -> u32 {
        self.0
    }
}
