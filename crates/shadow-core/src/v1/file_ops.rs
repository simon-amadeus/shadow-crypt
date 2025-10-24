use crate::{
    errors::HeaderError,
    v1::{file::EncryptedFile, header_ops},
};

pub fn get_encrypted_file_from_bytes(bytes: &[u8]) -> Result<EncryptedFile, HeaderError> {
    let header = header_ops::try_deserialize(bytes)?;
    let header_length = header.header_length as usize;

    let ciphertext = bytes[header_length..].to_vec();

    Ok(EncryptedFile::new(header, ciphertext))
}
