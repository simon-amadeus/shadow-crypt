use std::mem;

use crate::v1::key::KeyDerivationParams;

/// Complete v1 file header
#[derive(Debug, Clone)]
pub struct FileHeader {
    pub magic: [u8; 6],                  // 6 bytes: "SHADOW"
    pub version: u8,                     // 1 byte: Version number (1)
    pub header_length: u32,              // 4 byte: Total header size
    pub salt: [u8; 16],                  // 16 bytes: Argon2id salt
    pub kdf_memory: u32,                 // 4 bytes: Argon2id memory parameter
    pub kdf_iterations: u32,             // 4 bytes: Argon2id iterations parameter
    pub kdf_parallelism: u32,            // 4 bytes: Argon2id parallelism parameter
    pub kdf_key_length: u8,              // 1 byte: XChaCha20 key length
    pub content_nonce: [u8; 24],         // 24 bytes: XChaCha20 nonce
    pub filename_nonce: [u8; 24],        // 24 bytes: XChaCha20 nonce for filename
    pub filename_ciphertext_length: u16, // 2 bytes: Length of encrypted filename ciphertext
    pub filename_ciphertext: Vec<u8>,    // Encrypted filename ciphertext (variable length)
}

impl FileHeader {
    pub fn new(
        salt: [u8; 16],
        kdf_params: KeyDerivationParams,
        content_nonce: [u8; 24],
        filename_nonce: [u8; 24],
        filename_ciphertext: Vec<u8>,
    ) -> Self {
        let filename_ciphertext_length = filename_ciphertext.len() as u16;
        let size =
            mem::size_of::<FileHeader>() + filename_ciphertext.len() - mem::size_of::<Vec<u8>>();

        FileHeader {
            magic: *b"SHADOW",
            version: 1,
            header_length: size as u32,
            salt,
            kdf_memory: kdf_params.memory_cost,
            kdf_iterations: kdf_params.time_cost,
            kdf_parallelism: kdf_params.parallelism,
            kdf_key_length: kdf_params.key_size,
            content_nonce,
            filename_nonce,
            filename_ciphertext_length,
            filename_ciphertext,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values_are_correct() {
        let header = FileHeader::new(
            [0u8; 16],
            KeyDerivationParams::test_defaults(),
            [0u8; 24],
            [0u8; 24],
            vec![1, 2, 3, 4],
        );

        assert_eq!(&header.magic, b"SHADOW");
        assert_eq!(header.version, 1);
    }

    #[test]
    fn header_size_is_calculated_correctly() {
        let filename_ciphertext = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let header = FileHeader::new(
            [0u8; 16],
            KeyDerivationParams::test_defaults(),
            [0u8; 24],
            [0u8; 24],
            filename_ciphertext.clone(),
        );

        let expected_size = (mem::size_of::<FileHeader>() + filename_ciphertext.len()
            - mem::size_of::<Vec<u8>>()) as u32;

        assert_eq!(header.header_length, expected_size);
    }
}
