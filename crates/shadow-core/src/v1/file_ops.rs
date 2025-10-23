use crate::{
    errors::HeaderError,
    memory::SecureBytes,
    v1::{file::EncryptedFile, header_ops},
};

pub fn get_encrypted_file_from_bytes(bytes: &SecureBytes) -> Result<EncryptedFile, HeaderError> {
    let header = header_ops::try_deserialize(bytes.as_slice())?;
    let header_length = header.header_length as usize;

    let ciphertext = bytes.as_slice()[header_length..].to_vec();

    Ok(EncryptedFile::new(header, ciphertext))
}
