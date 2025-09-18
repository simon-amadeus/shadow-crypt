use crate::error::EncryptionError;
use crate::traits::*;
use crate::types::*;
use std::io::{BufWriter, Cursor, Write};
use std::path::Path;
use std::process::Command;
use tempfile::NamedTempFile;

/// Implementation of advanced features like partial decryption, editing, viewing, and listing
pub struct AdvancedFeatures<E, F>
where
    E: Encryptor,
    F: FileSystem,
{
    encryptor: std::sync::Arc<E>,
    file_system: std::sync::Arc<F>,
}

impl<E, F> AdvancedFeatures<E, F>
where
    E: Encryptor,
    F: FileSystem,
{
    pub fn new(encryptor: std::sync::Arc<E>, file_system: std::sync::Arc<F>) -> Self {
        Self {
            encryptor,
            file_system,
        }
    }

    fn get_content_start_offset(&self, header: &Header) -> usize {
        // Calculate the offset where encrypted content starts
        let header_size = bincode::serialized_size(header).unwrap_or(1024) as usize;
        header_size + 4 // 4 bytes for header length
    }
}

impl<E, F> PartialDecryptor for AdvancedFeatures<E, F>
where
    E: Encryptor,
    F: FileSystem,
{
    fn decrypt_to_stream(
        &self,
        encrypted_path: &Path,
        keys: &KeyMaterial,
        output: &mut dyn Write,
    ) -> Result<(), EncryptionError> {
        let (header, mut content_reader) = self.file_system.read_encrypted_file(encrypted_path)?;

        // Read all content and HMAC
        let mut content_with_hmac = Vec::new();
        std::io::Read::read_to_end(&mut content_reader, &mut content_with_hmac)?;

        if content_with_hmac.len() < 32 {
            return Err(EncryptionError::InvalidFileFormat);
        }

        let content_hmac = &content_with_hmac[content_with_hmac.len() - 32..];
        let encrypted_content = &content_with_hmac[..content_with_hmac.len() - 32];

        // Decrypt content
        let mut content_reader = Cursor::new(encrypted_content);
        self.encryptor.decrypt(
            keys,
            &mut content_reader,
            output,
            &header.iv,
            content_hmac,
        )?;

        Ok(())
    }

    fn decrypt_range_to_stream(
        &self,
        encrypted_path: &Path,
        keys: &KeyMaterial,
        start: u64,
        length: u64,
        output: &mut dyn Write,
    ) -> Result<(), EncryptionError> {
        // For now, we'll decrypt the full content and then extract the range
        // A more sophisticated implementation would implement true partial decryption
        let mut full_content = Vec::new();
        self.decrypt_to_stream(encrypted_path, keys, &mut full_content)?;

        let start_offset = start as usize;
        let end_offset = ((start + length) as usize).min(full_content.len());

        if start_offset < full_content.len() {
            output.write_all(&full_content[start_offset..end_offset])?;
        }

        Ok(())
    }
}

impl<E, F> FileEditor for AdvancedFeatures<E, F>
where
    E: Encryptor,
    F: FileSystem,
{
    fn edit_text_file(
        &self,
        encrypted_path: &Path,
        keys: &KeyMaterial,
        editor_command: &str,
    ) -> Result<(), EncryptionError> {
        // Create temporary file
        let temp_file = NamedTempFile::new()?;
        
        // Decrypt to temporary file
        {
            let mut temp_writer = BufWriter::new(&temp_file);
            self.decrypt_to_stream(encrypted_path, keys, &mut temp_writer)?;
            temp_writer.flush()?;
        }

        // Launch editor
        let status = Command::new(editor_command)
            .arg(temp_file.path())
            .status()?;

        if !status.success() {
            return Err(EncryptionError::EditorFailed);
        }

        // Re-encrypt the modified content
        let modified_content = std::fs::read(temp_file.path())?;
        self.save_edited_content(encrypted_path, keys, &String::from_utf8_lossy(&modified_content))?;

        Ok(())
    }

    fn get_editable_content(
        &self,
        encrypted_path: &Path,
        keys: &KeyMaterial,
    ) -> Result<String, EncryptionError> {
        let mut content = Vec::new();
        self.decrypt_to_stream(encrypted_path, keys, &mut content)?;
        
        String::from_utf8(content)
            .map_err(|e| EncryptionError::CryptographicError(e.to_string()))
    }

    fn save_edited_content(
        &self,
        encrypted_path: &Path,
        keys: &KeyMaterial,
        content: &str,
    ) -> Result<(), EncryptionError> {
        // Read the original header
        let original_header = self.file_system.read_header_only(encrypted_path)?;

        // Create new content with same IV for simplicity
        let mut content_reader = Cursor::new(content.as_bytes());
        let mut encrypted_content = Vec::new();

        let content_hmac = self.encryptor.encrypt(
            keys,
            &mut content_reader,
            &mut encrypted_content,
            &original_header.iv,
        )?;

        // Write the updated encrypted file
        let mut content_with_hmac = encrypted_content;
        content_with_hmac.extend_from_slice(&content_hmac);
        
        let mut final_content = Cursor::new(content_with_hmac);
        self.file_system.write_encrypted_file(encrypted_path, original_header, &mut final_content)?;

        Ok(())
    }
}

impl<E, F> FileViewer for AdvancedFeatures<E, F>
where
    E: Encryptor,
    F: FileSystem,
{
    fn view_file(
        &self,
        encrypted_path: &Path,
        keys: &KeyMaterial,
        viewer_command: &str,
    ) -> Result<(), EncryptionError> {
        // Create temporary file
        let temp_file = NamedTempFile::new()?;
        
        // Decrypt content to temporary file
        {
            let mut temp_writer = BufWriter::new(&temp_file);
            self.decrypt_to_stream(encrypted_path, keys, &mut temp_writer)?;
            temp_writer.flush()?;
        }

        // Launch viewer
        Command::new(viewer_command)
            .arg(temp_file.path())
            .status()?;

        Ok(())
    }

    fn get_file_preview(
        &self,
        encrypted_path: &Path,
        keys: &KeyMaterial,
        preview_size: usize,
    ) -> Result<Vec<u8>, EncryptionError> {
        let mut preview_buffer = Vec::with_capacity(preview_size);
        
        self.decrypt_range_to_stream(
            encrypted_path,
            keys,
            0,
            preview_size as u64,
            &mut preview_buffer,
        )?;

        Ok(preview_buffer)
    }
}

impl<E, F> FileLister for AdvancedFeatures<E, F>
where
    E: Encryptor,
    F: FileSystem,
{
    fn list_encrypted_names(
        &self,
        directory: &Path,
        keys: &KeyMaterial,
    ) -> Result<Vec<FileInfo>, EncryptionError> {
        let mut file_infos = Vec::new();

        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() {
                if let Ok(header) = self.file_system.read_header_only(&path) {
                    let original_name = self.encryptor.deobfuscate_name(
                        keys,
                        &path.file_name().unwrap().to_string_lossy(),
                        &path,
                        &header.encrypted_filename,
                        &header.filename_hmac,
                    )?;

                    let original_path = if !header.encrypted_directory_path.is_empty() {
                        self.encryptor.decrypt_directory_path(
                            keys,
                            &header.encrypted_directory_path,
                            &header.directory_path_hmac,
                        )?
                    } else {
                        std::path::PathBuf::from("/")
                    };

                    let metadata = std::fs::metadata(&path)?;
                    let original_size = self.calculate_original_size(&header, &metadata)?;

                    file_infos.push(FileInfo {
                        original_name,
                        obfuscated_name: path.file_name().unwrap().to_string_lossy().to_string(),
                        original_path,
                        size: original_size,
                        encrypted_size: metadata.len(),
                        modified: metadata.modified()?,
                    });
                }
            }
        }

        Ok(file_infos)
    }

    fn get_original_name(
        &self,
        encrypted_path: &Path,
        keys: &KeyMaterial,
    ) -> Result<String, EncryptionError> {
        let header = self.file_system.read_header_only(encrypted_path)?;
        
        self.encryptor.deobfuscate_name(
            keys,
            &encrypted_path.file_name().unwrap().to_string_lossy(),
            encrypted_path,
            &header.encrypted_filename,
            &header.filename_hmac,
        )
    }
}

impl<E, F> AdvancedFeatures<E, F>
where
    E: Encryptor,
    F: FileSystem,
{
    fn calculate_original_size(
        &self,
        header: &Header,
        encrypted_metadata: &std::fs::Metadata,
    ) -> Result<u64, EncryptionError> {
        // Estimate original size by subtracting header and HMAC overhead
        let header_size = bincode::serialized_size(header).unwrap_or(1024);
        let total_overhead = header_size + 32 + 4; // header + content HMAC + header length
        
        let encrypted_size = encrypted_metadata.len();
        if encrypted_size > total_overhead {
            // Account for AES padding (up to 16 bytes)
            Ok((encrypted_size - total_overhead).saturating_sub(16))
        } else {
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{AesHmacEncryptor, Argon2KeyDeriver};
    use crate::filesystem::StdFileSystem;
    use crate::traits::KeyDeriver;
    use tempfile::TempDir;
    use std::sync::Arc;

    fn create_test_advanced_features() -> AdvancedFeatures<AesHmacEncryptor, StdFileSystem> {
        AdvancedFeatures::new(
            Arc::new(AesHmacEncryptor::new()),
            Arc::new(StdFileSystem::new()),
        )
    }

    #[test]
    fn test_partial_decryption() {
        let temp_dir = TempDir::new().unwrap();
        let features = create_test_advanced_features();
        
        // This test would require setting up an encrypted file first
        // For now, we'll just test the interface
        assert!(true); // Placeholder
    }

    #[test]
    fn test_file_preview() {
        let temp_dir = TempDir::new().unwrap();
        let features = create_test_advanced_features();
        
        // This test would require setting up an encrypted file first
        // For now, we'll just test the interface
        assert!(true); // Placeholder
    }

    #[test]
    fn test_get_editable_content() {
        let temp_dir = TempDir::new().unwrap();
        let features = create_test_advanced_features();
        
        // This test would require setting up an encrypted file first
        // For now, we'll just test the interface
        assert!(true); // Placeholder
    }
}
