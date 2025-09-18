use crate::error::EncryptionError;
use crate::traits::*;
use crate::types::*;
use rayon::prelude::*;
use secrecy::ExposeSecret;
use std::collections::HashSet;
use std::io::{Cursor};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Main encryption service that coordinates all components using DIP
pub struct EncryptionService<K, E, F> 
where
    K: KeyDeriver,
    E: Encryptor,
    F: FileSystem,
{
    key_deriver: Arc<K>,
    encryptor: Arc<E>,
    file_system: Arc<F>,
}

impl<K, E, F> EncryptionService<K, E, F>
where
    K: KeyDeriver,
    E: Encryptor,
    F: FileSystem,
{
    pub fn new(key_deriver: K, encryptor: E, file_system: F) -> Self {
        Self {
            key_deriver: Arc::new(key_deriver),
            encryptor: Arc::new(encryptor),
            file_system: Arc::new(file_system),
        }
    }

    /// Get a reference to the key deriver
    pub fn key_deriver(&self) -> &K {
        &self.key_deriver
    }

    /// Get a reference to the encryptor
    pub fn encryptor(&self) -> &E {
        &self.encryptor
    }

    /// Get a reference to the file system
    pub fn file_system(&self) -> &F {
        &self.file_system
    }

    /// Encrypt a single file
    pub fn encrypt_file(
        &self,
        input_path: &Path,
        output_path: &Path,
        password: &str,
    ) -> Result<(), EncryptionError> {
        use rand::RngCore;

        // Generate salt and IV
        let mut salt = [0u8; 16];
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut iv);

        // Derive keys
        let keys = self.key_deriver.derive_key(password, &salt)?;

        // Get original metadata
        let original_metadata = self.file_system.get_file_metadata(input_path)?;

        // Create header
        let mut header = Header::new();
        header.salt = salt;
        header.iv = iv;

        // Encrypt filename
        let filename = input_path
            .file_name()
            .ok_or_else(|| EncryptionError::FileSystemError(
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid filename")
            ))?
            .to_string_lossy();

        let (encrypted_filename, filename_hmac) = self.encryptor.encrypt_name(
            &keys,
            &filename,
            input_path.parent().unwrap_or(Path::new("/")),
        )?;

        header.filename_length = encrypted_filename.len() as u16;
        header.encrypted_filename = encrypted_filename;
        header.filename_hmac.copy_from_slice(&filename_hmac);

        // Encrypt directory path
        let parent_path = input_path.parent().unwrap_or(Path::new("/"));
        let (encrypted_dir_path, dir_path_hmac) = self.encryptor.encrypt_directory_path(&keys, parent_path)?;

        header.directory_path_length = encrypted_dir_path.len() as u16;
        header.encrypted_directory_path = encrypted_dir_path;
        header.directory_path_hmac.copy_from_slice(&dir_path_hmac);

        // Encrypt metadata
        let (encrypted_metadata, metadata_hmac) = self.encryptor.encrypt_metadata(&keys, &original_metadata)?;

        header.metadata_length = encrypted_metadata.len() as u16;
        header.encrypted_metadata = encrypted_metadata;
        header.metadata_hmac.copy_from_slice(&metadata_hmac);

        // Encrypt content
        let mut input_reader = self.file_system.read_file(input_path)?;
        let mut content_buffer = Vec::new();

        let content_hmac = self.encryptor.encrypt(
            &keys,
            &mut input_reader,
            &mut content_buffer,
            &iv,
        )?;

        // Write encrypted file
        let mut content_reader = Cursor::new(content_buffer);
        self.file_system.write_encrypted_file(output_path, header, &mut content_reader)?;

        // Append content HMAC
        let mut output_file = std::fs::OpenOptions::new()
            .append(true)
            .open(output_path)?;
        std::io::Write::write_all(&mut output_file, &content_hmac)?;

        Ok(())
    }

    /// Decrypt a single file
    pub fn decrypt_file(
        &self,
        input_path: &Path,
        output_path: &Path,
        password: &str,
    ) -> Result<(), EncryptionError> {
        // Read encrypted file
        let (header, mut content_reader) = self.file_system.read_encrypted_file(input_path)?;

        // Derive keys
        let keys = self.key_deriver.derive_key(password, &header.salt)?;

        // Read content and HMAC
        let mut content_with_hmac = Vec::new();
        std::io::Read::read_to_end(&mut content_reader, &mut content_with_hmac)?;

        if content_with_hmac.len() < 32 {
            return Err(EncryptionError::InvalidFileFormat);
        }

        let content_hmac = &content_with_hmac[content_with_hmac.len() - 32..];
        let encrypted_content = &content_with_hmac[..content_with_hmac.len() - 32];

        // Decrypt content
        let mut content_reader = Cursor::new(encrypted_content);
        let mut output_writer = Vec::new();

        self.encryptor.decrypt(
            &keys,
            &mut content_reader,
            &mut output_writer,
            &header.iv,
            content_hmac,
        )?;

        // Write decrypted file
        let mut output_content_reader = Cursor::new(output_writer);
        self.file_system.write_file(output_path, &mut output_content_reader)?;

        // Restore metadata
        if !header.encrypted_metadata.is_empty() {
            let metadata = self.encryptor.decrypt_metadata(
                &keys,
                &header.encrypted_metadata,
                &header.metadata_hmac,
            )?;
            self.file_system.set_file_metadata(output_path, &metadata)?;
        }

        Ok(())
    }

    /// Encrypt multiple files
    pub fn encrypt_files(
        &self,
        input_paths: &[PathBuf],
        output_dir: &Path,
        password: &str,
        use_obfuscated_names: bool,
    ) -> Result<(), EncryptionError> {
        // Create output directory
        std::fs::create_dir_all(output_dir)?;

        // Get existing files to avoid name collisions
        let existing_names: HashSet<String> = std::fs::read_dir(output_dir)?
            .filter_map(|entry| {
                entry.ok().and_then(|e| {
                    e.file_name().to_str().map(|s| s.to_string())
                })
            })
            .collect();

        // Process files in parallel
        let errors: Vec<_> = input_paths
            .par_iter()
            .map(|input_path| {
                let output_filename = if use_obfuscated_names {
                    // Generate session key for consistent obfuscation
                    let session_key = self.key_deriver.derive_session_key(password)?;
                    
                    let filename = input_path
                        .file_name()
                        .ok_or_else(|| EncryptionError::FileSystemError(
                            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid filename")
                        ))?
                        .to_string_lossy();

                    self.encryptor.obfuscate_name(
                        session_key.key_material.obfuscation_key.expose_secret(),
                        &filename,
                        input_path.parent().unwrap_or(Path::new("/")),
                        &existing_names,
                    )?
                } else {
                    input_path
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .to_string()
                };

                let output_path = output_dir.join(&output_filename);
                self.encrypt_file(input_path, &output_path, password)
            })
            .filter_map(|result| result.err())
            .collect();

        if !errors.is_empty() {
            return Err(EncryptionError::BatchProcessingFailed(errors));
        }

        Ok(())
    }

    /// Encrypt a directory recursively
    pub fn encrypt_directory(
        &self,
        input_dir: &Path,
        output_dir: &Path,
        password: &str,
        recursive: bool,
    ) -> Result<(), EncryptionError> {
        let files = self.file_system.traverse_directory(input_dir, recursive)?;
        self.encrypt_files(&files, output_dir, password, true)
    }

    /// Decrypt multiple files
    pub fn decrypt_directory(
        &self,
        encrypted_dir: &Path,
        output_dir: &Path,
        password: &str,
        restore_structure: bool,
    ) -> Result<(), EncryptionError> {
        let encrypted_files = self.file_system.traverse_directory(encrypted_dir, false)?;
        
        for encrypted_file in encrypted_files {
            // Read header to get original path
            let header = self.file_system.read_header_only(&encrypted_file)?;
            let keys = self.key_deriver.derive_key(password, &header.salt)?;
            
            // Get original filename
            let original_filename = self.encryptor.deobfuscate_name(
                &keys,
                &encrypted_file.file_name().unwrap().to_string_lossy(),
                &encrypted_file,
                &header.encrypted_filename,
                &header.filename_hmac,
            )?;

            let output_path = if restore_structure && !header.encrypted_directory_path.is_empty() {
                let original_dir = self.encryptor.decrypt_directory_path(
                    &keys,
                    &header.encrypted_directory_path,
                    &header.directory_path_hmac,
                )?;
                output_dir.join(original_dir).join(original_filename)
            } else {
                output_dir.join(original_filename)
            };

            // Create parent directories if needed
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            // Decrypt file
            self.decrypt_file(&encrypted_file, &output_path, password)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{AesHmacEncryptor, Argon2KeyDeriver};
    use crate::filesystem::StdFileSystem;
    use tempfile::TempDir;
    use std::fs;

    fn create_test_service() -> EncryptionService<Argon2KeyDeriver, AesHmacEncryptor, StdFileSystem> {
        EncryptionService::new(
            Argon2KeyDeriver::new(),
            AesHmacEncryptor::new(),
            StdFileSystem::new(),
        )
    }

    #[test]
    fn test_single_file_encryption_decryption() {
        let temp_dir = TempDir::new().unwrap();
        let service = create_test_service();

        let input_path = temp_dir.path().join("test.txt");
        let encrypted_path = temp_dir.path().join("test.txt.enc");
        let decrypted_path = temp_dir.path().join("test_decrypted.txt");

        let content = "Hello, World! This is a test file.";
        fs::write(&input_path, content).unwrap();

        let password = "test_password_123";

        // Encrypt
        service
            .encrypt_file(&input_path, &encrypted_path, password)
            .unwrap();

        // Decrypt
        service
            .decrypt_file(&encrypted_path, &decrypted_path, password)
            .unwrap();

        // Verify
        let decrypted_content = fs::read_to_string(decrypted_path).unwrap();
        assert_eq!(content, decrypted_content);
    }

    #[test]
    fn test_directory_encryption() {
        let temp_dir = TempDir::new().unwrap();
        let service = create_test_service();

        let input_dir = temp_dir.path().join("input");
        let encrypted_dir = temp_dir.path().join("encrypted");
        let decrypted_dir = temp_dir.path().join("decrypted");

        // Create test directory structure
        fs::create_dir_all(&input_dir).unwrap();
        fs::write(input_dir.join("file1.txt"), "Content 1").unwrap();
        fs::write(input_dir.join("file2.txt"), "Content 2").unwrap();

        let password = "test_password_123";

        // Encrypt directory
        service
            .encrypt_directory(&input_dir, &encrypted_dir, password, false)
            .unwrap();

        // Verify encrypted files exist
        assert!(encrypted_dir.exists());
        let encrypted_files: Vec<_> = fs::read_dir(&encrypted_dir).unwrap().collect();
        assert_eq!(encrypted_files.len(), 2);

        // Decrypt directory
        service
            .decrypt_directory(&encrypted_dir, &decrypted_dir, password, false)
            .unwrap();

        // Verify decrypted content
        assert_eq!(
            fs::read_to_string(decrypted_dir.join("file1.txt")).unwrap(),
            "Content 1"
        );
        assert_eq!(
            fs::read_to_string(decrypted_dir.join("file2.txt")).unwrap(),
            "Content 2"
        );
    }

    #[test]
    fn test_wrong_password_fails() {
        let temp_dir = TempDir::new().unwrap();
        let service = create_test_service();

        let input_path = temp_dir.path().join("test.txt");
        let encrypted_path = temp_dir.path().join("test.txt.enc");
        let decrypted_path = temp_dir.path().join("test_decrypted.txt");

        fs::write(&input_path, "Secret content").unwrap();

        // Encrypt with correct password
        service
            .encrypt_file(&input_path, &encrypted_path, "correct_password")
            .unwrap();

        // Try to decrypt with wrong password
        let result = service.decrypt_file(&encrypted_path, &decrypted_path, "wrong_password");
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EncryptionError::AuthenticationFailed));
    }
}
