use std::mem;

use crate::v1::{
    header::{
        Argon2idSalt, EncryptedFileName, FileHeader, FileVersion, HeaderSize, Poly1305Tag,
        ShadowMagic, XChaCha20Nonce,
    },
    key::KeyDerivationParams,
};

pub fn serialize_header(header: &FileHeader) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(ShadowMagic::BYTES.as_ref());
    output.extend_from_slice(&FileVersion::as_u16().to_le_bytes());
    output.extend_from_slice(header.salt.as_bytes());
    output.extend_from_slice(header.content_nonce.as_bytes());
    output.extend_from_slice(header.content_tag.as_bytes());
    output.extend_from_slice(&header.encrypted_filename.serialize());
    output
}

pub fn get_header_size(data: &[u8]) -> Option<HeaderSize> {
    // Use FileHeader::min_size() as the single source of truth for fixed-size fields
    if data.len() < FileHeader::min_size() {
        return None;
    }

    // Calculate offset to the size field in EncryptedFileName
    let size_offset = FileHeader::min_size();

    // Extract the size field (u16) from the data
    let size_bytes = data
        .get(size_offset..size_offset + mem::size_of::<u16>())
        .and_then(|slice| slice.try_into().ok())?;
    let ciphertext_size = u16::from_le_bytes(size_bytes) as u32;

    // Verify that the data is long enough to include the ciphertext
    let total_size = FileHeader::min_size() as u32 + ciphertext_size;
    if data.len() < total_size as usize {
        return None;
    }

    Some(HeaderSize(total_size))
}

pub fn deserialize_header(data: &[u8]) -> Option<FileHeader> {
    // Ensure data is at least as long as the minimum header size
    if data.len() < FileHeader::min_size() {
        return None;
    }

    // Define offsets for each field
    let magic_end = ShadowMagic::size();
    let version_end = magic_end + FileVersion::size();
    let salt_end = version_end + Argon2idSalt::size();
    let key_params_end = salt_end + KeyDerivationParams::size();
    let content_nonce_end = key_params_end + XChaCha20Nonce::size();
    let content_tag_end = content_nonce_end + Poly1305Tag::size();
    let filename_nonce_end = content_tag_end + XChaCha20Nonce::size();
    let filename_tag_end = filename_nonce_end + Poly1305Tag::size();
    let filename_size_end = filename_tag_end + mem::size_of::<u16>();

    // Validate magic bytes
    let magic_bytes = data.get(0..magic_end)?;
    if magic_bytes != ShadowMagic::BYTES {
        return None;
    }

    // Validate version
    let version_bytes = data
        .get(magic_end..version_end)
        .and_then(|slice| slice.try_into().ok())?;
    let version = u16::from_le_bytes(version_bytes);
    if version != FileVersion::VALUE {
        return None;
    }

    // Extract salt
    let salt_bytes = data
        .get(version_end..salt_end)
        .and_then(|slice| slice.try_into().ok())?;
    let salt = Argon2idSalt::new(salt_bytes);

    let key_params = {
        let params_bytes = data
            .get(salt_end..key_params_end)
            .and_then(|slice| slice.try_into().ok())?;
        KeyDerivationParams::from_bytes(params_bytes)?
    };

    // Extract content nonce
    let content_nonce_bytes = data
        .get(salt_end..content_nonce_end)
        .and_then(|slice| slice.try_into().ok())?;
    let content_nonce = XChaCha20Nonce::new(content_nonce_bytes);

    // Extract content tag
    let content_tag_bytes = data
        .get(content_nonce_end..content_tag_end)
        .and_then(|slice| slice.try_into().ok())?;
    let content_tag = Poly1305Tag::new(content_tag_bytes);

    // Extract filename nonce
    let filename_nonce_bytes = data
        .get(content_tag_end..filename_nonce_end)
        .and_then(|slice| slice.try_into().ok())?;
    let filename_nonce = XChaCha20Nonce::new(filename_nonce_bytes);

    // Extract filename tag
    let filename_tag_bytes = data
        .get(filename_nonce_end..filename_tag_end)
        .and_then(|slice| slice.try_into().ok())?;
    let filename_tag = Poly1305Tag::new(filename_tag_bytes);

    // Extract filename size
    let filename_size_bytes = data
        .get(filename_tag_end..filename_size_end)
        .and_then(|slice| slice.try_into().ok())?;
    let filename_size = u16::from_le_bytes(filename_size_bytes) as usize;

    // Extract ciphertext
    let ciphertext = data
        .get(filename_size_end..filename_size_end + filename_size)
        .map(|slice| slice.to_vec())?;

    // Construct EncryptedFileName
    let encrypted_filename = EncryptedFileName::new(filename_nonce, filename_tag, ciphertext);

    // Construct FileHeader
    Some(FileHeader::new(
        salt,
        key_params,
        content_nonce,
        content_tag,
        encrypted_filename,
    ))
}
