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
