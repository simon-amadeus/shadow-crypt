use crate::error::EncryptionError;
use crate::traits::Encryptor;
use crate::types::{FileMetadata, KeyMaterial};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{Engine, engine::general_purpose};
use hmac::{Hmac, Mac};
use secrecy::ExposeSecret;
use sha2::Sha256;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// AES-256-CBC + HMAC-SHA256 encryption implementation
#[derive(Clone)]
pub struct AesHmacEncryptor;

impl AesHmacEncryptor {
    pub fn new() -> Self {
        Self
    }

    fn compute_hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| EncryptionError::CryptographicError(e.to_string()))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn verify_hmac(&self, key: &[u8], data: &[u8], expected: &[u8]) -> Result<(), EncryptionError> {
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| EncryptionError::CryptographicError(e.to_string()))?;
        mac.update(data);
        
        mac.verify_slice(expected)
            .map_err(|_| EncryptionError::AuthenticationFailed)
    }

    fn encrypt_data(&self, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let cipher = Aes256CbcEnc::new(key.into(), iv.into());
        Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(data))
    }

    fn decrypt_data(&self, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let cipher = Aes256CbcDec::new(key.into(), iv.into());
        cipher
            .decrypt_padded_vec_mut::<Pkcs7>(data)
            .map_err(|e| EncryptionError::CryptographicError(e.to_string()))
    }
}

impl Default for AesHmacEncryptor {
    fn default() -> Self {
        Self::new()
    }
}

impl Encryptor for AesHmacEncryptor {
    fn encrypt(
        &self,
        keys: &KeyMaterial,
        plaintext: &mut dyn Read,
        output: &mut dyn Write,
        iv: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let mut buffer = Vec::new();
        plaintext.read_to_end(&mut buffer)?;

        let encrypted = self.encrypt_data(
            keys.encryption_key.expose_secret(),
            iv,
            &buffer,
        )?;

        let hmac = self.compute_hmac(keys.hmac_key.expose_secret(), &encrypted)?;

        output.write_all(&encrypted)?;
        Ok(hmac)
    }

    fn decrypt(
        &self,
        keys: &KeyMaterial,
        ciphertext: &mut dyn Read,
        output: &mut dyn Write,
        iv: &[u8],
        hmac: &[u8],
    ) -> Result<(), EncryptionError> {
        let mut buffer = Vec::new();
        ciphertext.read_to_end(&mut buffer)?;

        self.verify_hmac(keys.hmac_key.expose_secret(), &buffer, hmac)?;

        let decrypted = self.decrypt_data(
            keys.encryption_key.expose_secret(),
            iv,
            &buffer,
        )?;

        output.write_all(&decrypted)?;
        Ok(())
    }

    fn decrypt_range(
        &self,
        _keys: &KeyMaterial,
        _ciphertext: &mut dyn Read,
        _output: &mut dyn Write,
        _start_byte: u64,
        _length: u64,
    ) -> Result<(), EncryptionError> {
        // For simplicity, we'll decrypt the entire content and then extract the range
        // In a production system, you might want to implement true partial decryption
        // For this implementation, we need the HMAC to verify first
        // In a real implementation, you'd store the HMAC separately or implement
        // a streaming approach with authentication
        Err(EncryptionError::PartialDecryptionNotSupported)
    }

    fn encrypt_name(
        &self,
        keys: &KeyMaterial,
        name: &str,
        _path: &Path,
    ) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
        use rand::RngCore;
        
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);

        let encrypted = self.encrypt_data(
            keys.encryption_key.expose_secret(),
            &iv,
            name.as_bytes(),
        )?;

        let mut data_with_iv = Vec::with_capacity(16 + encrypted.len());
        data_with_iv.extend_from_slice(&iv);
        data_with_iv.extend_from_slice(&encrypted);

        let hmac = self.compute_hmac(keys.hmac_key.expose_secret(), &data_with_iv)?;

        Ok((data_with_iv, hmac))
    }

    fn obfuscate_name(
        &self,
        key: &[u8],
        name: &str,
        path: &Path,
        existing_names: &HashSet<String>,
    ) -> Result<String, EncryptionError> {
        let mut counter = 0u32;
        
        loop {
            let input = if counter == 0 {
                format!("{}:{}", name, path.display())
            } else {
                format!("{}:{}:{}", name, path.display(), counter)
            };

            let hmac = self.compute_hmac(key, input.as_bytes())?;
            let obfuscated = general_purpose::URL_SAFE_NO_PAD.encode(&hmac[..20]);

            if !existing_names.contains(&obfuscated) {
                return Ok(obfuscated);
            }

            counter += 1;
            if counter > 1000 {
                return Err(EncryptionError::TooManyCollisions);
            }
        }
    }

    fn deobfuscate_name(
        &self,
        keys: &KeyMaterial,
        _obfuscated: &str,
        _path: &Path,
        ciphertext: &[u8],
        hmac: &[u8],
    ) -> Result<String, EncryptionError> {
        self.verify_hmac(keys.hmac_key.expose_secret(), ciphertext, hmac)?;

        if ciphertext.len() < 16 {
            return Err(EncryptionError::CryptographicError(
                "Ciphertext too short for IV".to_string(),
            ));
        }

        let iv = &ciphertext[0..16];
        let encrypted_name = &ciphertext[16..];

        let decrypted = self.decrypt_data(
            keys.encryption_key.expose_secret(),
            iv,
            encrypted_name,
        )?;

        String::from_utf8(decrypted)
            .map_err(|e| EncryptionError::CryptographicError(e.to_string()))
    }

    fn encrypt_directory_path(
        &self,
        keys: &KeyMaterial,
        path: &Path,
    ) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
        self.encrypt_name(keys, &path.display().to_string(), path)
    }

    fn encrypt_metadata(
        &self,
        keys: &KeyMaterial,
        metadata: &FileMetadata,
    ) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
        use rand::RngCore;
        
        let serialized = bincode::serialize(metadata)?;
        
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);

        let encrypted = self.encrypt_data(
            keys.encryption_key.expose_secret(),
            &iv,
            &serialized,
        )?;

        let mut data_with_iv = Vec::with_capacity(16 + encrypted.len());
        data_with_iv.extend_from_slice(&iv);
        data_with_iv.extend_from_slice(&encrypted);

        let hmac = self.compute_hmac(keys.hmac_key.expose_secret(), &data_with_iv)?;

        Ok((data_with_iv, hmac))
    }

    fn decrypt_directory_path(
        &self,
        keys: &KeyMaterial,
        ciphertext: &[u8],
        hmac: &[u8],
    ) -> Result<std::path::PathBuf, EncryptionError> {
        let decrypted_string = self.deobfuscate_name(keys, "", &std::path::Path::new(""), ciphertext, hmac)?;
        Ok(std::path::PathBuf::from(decrypted_string))
    }

    fn decrypt_metadata(
        &self,
        keys: &KeyMaterial,
        ciphertext: &[u8],
        hmac: &[u8],
    ) -> Result<FileMetadata, EncryptionError> {
        self.verify_hmac(keys.hmac_key.expose_secret(), ciphertext, hmac)?;

        if ciphertext.len() < 16 {
            return Err(EncryptionError::CryptographicError(
                "Ciphertext too short for IV".to_string(),
            ));
        }

        let iv = &ciphertext[0..16];
        let encrypted_metadata = &ciphertext[16..];

        let decrypted = self.decrypt_data(
            keys.encryption_key.expose_secret(),
            iv,
            encrypted_metadata,
        )?;

        let metadata: FileMetadata = bincode::deserialize(&decrypted)?;
        Ok(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2KeyDeriver;
    use crate::traits::KeyDeriver;
    use std::io::Cursor;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let deriver = Argon2KeyDeriver::new();
        let keys = deriver.derive_key("password", &[0u8; 16]).unwrap();
        let encryptor = AesHmacEncryptor::new();

        let plaintext = b"Hello, World!";
        let iv = [0u8; 16];

        let mut plaintext_reader = Cursor::new(plaintext);
        let mut encrypted_output = Vec::new();

        let hmac = encryptor
            .encrypt(&keys, &mut plaintext_reader, &mut encrypted_output, &iv)
            .unwrap();

        let mut ciphertext_reader = Cursor::new(&encrypted_output);
        let mut decrypted_output = Vec::new();

        encryptor
            .decrypt(&keys, &mut ciphertext_reader, &mut decrypted_output, &iv, &hmac)
            .unwrap();

        assert_eq!(plaintext, decrypted_output.as_slice());
    }

    #[test]
    fn test_filename_encryption() {
        let deriver = Argon2KeyDeriver::new();
        let keys = deriver.derive_key("password", &[0u8; 16]).unwrap();
        let encryptor = AesHmacEncryptor::new();

        let filename = "secret_document.txt";
        let path = std::path::Path::new("/home/user");

        let (encrypted, hmac) = encryptor.encrypt_name(&keys, filename, path).unwrap();
        let decrypted = encryptor
            .deobfuscate_name(&keys, "", path, &encrypted, &hmac)
            .unwrap();

        assert_eq!(filename, decrypted);
    }

    #[test]
    fn test_obfuscation_collision_resistance() {
        let encryptor = AesHmacEncryptor::new();
        let key = [0u8; 32];
        let path = std::path::Path::new("/test");
        let existing_names = HashSet::new();

        let name1 = "file1.txt";
        let name2 = "file2.txt";

        let obfuscated1 = encryptor
            .obfuscate_name(&key, name1, path, &existing_names)
            .unwrap();
        let obfuscated2 = encryptor
            .obfuscate_name(&key, name2, path, &existing_names)
            .unwrap();

        assert_ne!(obfuscated1, obfuscated2);
    }
}
