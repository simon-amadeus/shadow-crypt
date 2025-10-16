// shadow-core/src/format/v1/types.rs
// Version 1.0 format-specific types and structures
// All v1 format types live here for maximum cohesion

/// Complete file header as defined in SHADOW_SPECIFICATION_v1.0.md
#[derive(Debug, Clone)]
pub struct FileHeader {
    pub magic: [u8; 8],          // "SHADOW01"
    pub algorithm_id: u8,        // 0x01 for XChaCha20-Poly1305
    pub obfuscation_flag: u8,    // 0x00 or 0x01
    pub content_hash: [u8; 32],  // SHA-256 of original content
    pub filename_data: FilenameData,
    pub salt: [u8; 16],          // Argon2id salt
    pub content_nonce: [u8; 24], // XChaCha20-Poly1305 nonce
}

/// Filename data that can be either plaintext or encrypted
#[derive(Debug, Clone)]
pub enum FilenameData {
    /// Plaintext filename when obfuscation is disabled
    Plaintext(String),
    /// Encrypted filename when obfuscation is enabled
    Encrypted {
        ciphertext: Vec<u8>,
        nonce: [u8; 24],
    },
}

/// Complete encrypted file structure for v1 format
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    pub header: FileHeader,
    pub ciphertext: Vec<u8>,
    pub suggested_filename: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_header_construction() {
        let header = FileHeader {
            magic: *b"SHADOW01",
            algorithm_id: 0x01,
            obfuscation_flag: 0x00,
            content_hash: [0u8; 32],
            filename_data: FilenameData::Plaintext("test.txt".to_string()),
            salt: [0u8; 16],
            content_nonce: [0u8; 24],
        };
        
        assert_eq!(header.magic, *b"SHADOW01");
        assert_eq!(header.algorithm_id, 0x01);
    }

    #[test]
    fn test_filename_data_plaintext() {
        let filename_data = FilenameData::Plaintext("document.pdf".to_string());
        
        match filename_data {
            FilenameData::Plaintext(name) => {
                assert_eq!(name, "document.pdf");
            }
            _ => panic!("Expected plaintext filename data"),
        }
    }

    #[test]
    fn test_filename_data_encrypted() {
        let ciphertext = vec![1, 2, 3, 4, 5];
        let nonce = [42u8; 24];
        let filename_data = FilenameData::Encrypted {
            ciphertext: ciphertext.clone(),
            nonce,
        };
        
        match filename_data {
            FilenameData::Encrypted { ciphertext: ct, nonce: n } => {
                assert_eq!(ct, ciphertext);
                assert_eq!(n, nonce);
            }
            _ => panic!("Expected encrypted filename data"),
        }
    }
}