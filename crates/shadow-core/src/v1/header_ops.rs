use crate::errors::HeaderError;

use super::header::FileHeader;

pub fn serialize(header: &FileHeader) -> Vec<u8> {
    let mut bytes = Vec::new();

    bytes.extend_from_slice(header.magic.as_slice());
    bytes.push(header.version);
    bytes.extend_from_slice(header.header_length.to_le_bytes().as_slice());
    bytes.extend_from_slice(header.salt.as_slice());
    bytes.extend_from_slice(header.kdf_memory.to_le_bytes().as_slice());
    bytes.extend_from_slice(header.kdf_iterations.to_le_bytes().as_slice());
    bytes.extend_from_slice(header.kdf_parallelism.to_le_bytes().as_slice());
    bytes.push(header.kdf_key_length);
    bytes.extend_from_slice(header.content_nonce.as_slice());
    bytes.extend_from_slice(header.filename_nonce.as_slice());
    bytes.extend_from_slice(header.filename_ciphertext_length.to_le_bytes().as_slice());
    bytes.extend_from_slice(header.filename_ciphertext.as_slice());

    bytes
}

pub fn is_shadow_file(bytes: &[u8]) -> Result<bool, HeaderError> {
    let magic = get_magic_from_bytes(bytes)?;
    Ok(&magic == b"SHADOW")
}

fn get_magic_from_bytes(bytes: &[u8]) -> Result<[u8; 6], HeaderError> {
    if bytes.len() < 6 {
        return Err(HeaderError::InsufficientBytes);
    }
    let magic_bytes = &bytes[0..6];
    let mut magic = [0u8; 6];
    magic.copy_from_slice(magic_bytes);
    Ok(magic)
}

fn get_length_from_bytes(bytes: &[u8]) -> Result<u32, HeaderError> {
    if bytes.len() < 11 {
        return Err(HeaderError::InsufficientBytes);
    }
    let length_bytes = &bytes[7..11];
    let length = u32::from_le_bytes(
        length_bytes
            .try_into()
            .map_err(|_| HeaderError::InvalidData)?,
    );
    Ok(length)
}

pub fn try_deserialize(bytes: &[u8]) -> Result<FileHeader, HeaderError> {
    if bytes.len() < FileHeader::min_length() as usize {
        return Err(HeaderError::InsufficientBytes);
    }

    let length: u32 = get_length_from_bytes(bytes)?;

    if bytes.len() < length as usize {
        return Err(HeaderError::InsufficientBytes);
    }

    match deserialize(bytes) {
        Some(header) => Ok(header),
        None => Err(HeaderError::InvalidData),
    }
}

fn deserialize(bytes: &[u8]) -> Option<FileHeader> {
    if bytes.len() < FileHeader::min_length() as usize {
        return None;
    }
    let magic = bytes[0..6].try_into().ok()?;
    let version = bytes[6];
    let header_length = u32::from_le_bytes(bytes[7..11].try_into().ok()?);
    let salt = bytes[11..27].try_into().ok()?;
    let kdf_memory = u32::from_le_bytes(bytes[27..31].try_into().ok()?);
    let kdf_iterations = u32::from_le_bytes(bytes[31..35].try_into().ok()?);
    let kdf_parallelism = u32::from_le_bytes(bytes[35..39].try_into().ok()?);
    let kdf_key_length = bytes[39];
    let content_nonce = bytes[40..64].try_into().ok()?;
    let filename_nonce = bytes[64..88].try_into().ok()?;
    let filename_ciphertext_length = u16::from_le_bytes(bytes[88..90].try_into().ok()?);

    let expected_length: usize = FileHeader::min_length() + filename_ciphertext_length as usize;

    if header_length != expected_length as u32 {
        return None;
    }

    if bytes.len() < expected_length {
        return None;
    }

    let filename_ciphertext = bytes[FileHeader::min_length()
        ..(FileHeader::min_length() + filename_ciphertext_length as usize)]
        .to_vec();

    Some(FileHeader {
        magic,
        version,
        header_length,
        salt,
        kdf_memory,
        kdf_iterations,
        kdf_parallelism,
        kdf_key_length,
        content_nonce,
        filename_nonce,
        filename_ciphertext_length,
        filename_ciphertext,
    })
}
