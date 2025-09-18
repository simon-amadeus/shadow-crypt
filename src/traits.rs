use crate::error::EncryptionError;
use crate::types::*;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Trait for key derivation operations
pub trait KeyDeriver: Send + Sync {
    fn derive_key(&self, password: &str, salt: &[u8]) -> Result<KeyMaterial, EncryptionError>;
    fn derive_session_key(&self, password: &str) -> Result<SessionKey, EncryptionError>;
}

/// Trait for core encryption/decryption operations
pub trait Encryptor: Send + Sync {
    // Core encryption/decryption
    fn encrypt(
        &self,
        keys: &KeyMaterial,
        plaintext: &mut dyn Read,
        output: &mut dyn Write,
        iv: &[u8],
    ) -> Result<Vec<u8>, EncryptionError>;

    fn decrypt(
        &self,
        keys: &KeyMaterial,
        ciphertext: &mut dyn Read,
        output: &mut dyn Write,
        iv: &[u8],
        hmac: &[u8],
    ) -> Result<(), EncryptionError>;

    // Partial decryption for advanced features
    fn decrypt_range(
        &self,
        keys: &KeyMaterial,
        ciphertext: &mut dyn Read,
        output: &mut dyn Write,
        start_byte: u64,
        length: u64,
    ) -> Result<(), EncryptionError>;

    // Filename handling
    fn encrypt_name(
        &self,
        keys: &KeyMaterial,
        name: &str,
        path: &Path,
    ) -> Result<(Vec<u8>, Vec<u8>), EncryptionError>;

    fn obfuscate_name(
        &self,
        key: &[u8],
        name: &str,
        path: &Path,
        existing_names: &HashSet<String>,
    ) -> Result<String, EncryptionError>;

    fn deobfuscate_name(
        &self,
        keys: &KeyMaterial,
        obfuscated: &str,
        path: &Path,
        ciphertext: &[u8],
        hmac: &[u8],
    ) -> Result<String, EncryptionError>;

    // Directory and metadata handling
    fn encrypt_directory_path(
        &self,
        keys: &KeyMaterial,
        path: &Path,
    ) -> Result<(Vec<u8>, Vec<u8>), EncryptionError>;

    fn encrypt_metadata(
        &self,
        keys: &KeyMaterial,
        metadata: &FileMetadata,
    ) -> Result<(Vec<u8>, Vec<u8>), EncryptionError>;

    fn decrypt_directory_path(
        &self,
        keys: &KeyMaterial,
        ciphertext: &[u8],
        hmac: &[u8],
    ) -> Result<PathBuf, EncryptionError>;

    fn decrypt_metadata(
        &self,
        keys: &KeyMaterial,
        ciphertext: &[u8],
        hmac: &[u8],
    ) -> Result<FileMetadata, EncryptionError>;
}

/// Trait for file system operations
pub trait FileSystem: Send + Sync {
    // Basic operations
    fn read_file(&self, path: &Path) -> Result<Box<dyn Read>, EncryptionError>;
    fn write_file(&self, path: &Path, content: &mut dyn Read) -> Result<(), EncryptionError>;
    fn traverse_directory(&self, root: &Path, recursive: bool) -> Result<Vec<PathBuf>, EncryptionError>;

    // Enhanced operations
    fn read_file_range(
        &self,
        path: &Path,
        start: u64,
        length: u64,
    ) -> Result<Box<dyn Read>, EncryptionError>;

    fn write_encrypted_file(
        &self,
        path: &Path,
        header: Header,
        content: &mut dyn Read,
    ) -> Result<(), EncryptionError>;

    fn read_encrypted_file(&self, path: &Path) -> Result<(Header, Box<dyn Read>), EncryptionError>;

    fn read_header_only(&self, path: &Path) -> Result<Header, EncryptionError>;

    fn get_file_metadata(&self, path: &Path) -> Result<FileMetadata, EncryptionError>;
    fn set_file_metadata(&self, path: &Path, metadata: &FileMetadata) -> Result<(), EncryptionError>;

    // Atomic operations
    fn atomic_write(&self, path: &Path, content: &mut dyn Read) -> Result<(), EncryptionError>;
    fn atomic_rename(&self, old: &Path, new: &Path) -> Result<(), EncryptionError>;
}

/// Trait for partial decryption capabilities
pub trait PartialDecryptor: Send + Sync {
    fn decrypt_to_stream(
        &self,
        encrypted_path: &Path,
        keys: &KeyMaterial,
        output: &mut dyn Write,
    ) -> Result<(), EncryptionError>;

    fn decrypt_range_to_stream(
        &self,
        encrypted_path: &Path,
        keys: &KeyMaterial,
        start: u64,
        length: u64,
        output: &mut dyn Write,
    ) -> Result<(), EncryptionError>;
}

/// Trait for file editing without full decryption
pub trait FileEditor: Send + Sync {
    fn edit_text_file(
        &self,
        encrypted_path: &Path,
        keys: &KeyMaterial,
        editor_command: &str,
    ) -> Result<(), EncryptionError>;

    fn get_editable_content(
        &self,
        encrypted_path: &Path,
        keys: &KeyMaterial,
    ) -> Result<String, EncryptionError>;

    fn save_edited_content(
        &self,
        encrypted_path: &Path,
        keys: &KeyMaterial,
        content: &str,
    ) -> Result<(), EncryptionError>;
}

/// Trait for file viewing without full decryption
pub trait FileViewer: Send + Sync {
    fn view_file(
        &self,
        encrypted_path: &Path,
        keys: &KeyMaterial,
        viewer_command: &str,
    ) -> Result<(), EncryptionError>;

    fn get_file_preview(
        &self,
        encrypted_path: &Path,
        keys: &KeyMaterial,
        preview_size: usize,
    ) -> Result<Vec<u8>, EncryptionError>;
}

/// Trait for listing encrypted files
pub trait FileLister: Send + Sync {
    fn list_encrypted_names(
        &self,
        directory: &Path,
        keys: &KeyMaterial,
    ) -> Result<Vec<FileInfo>, EncryptionError>;

    fn get_original_name(
        &self,
        encrypted_path: &Path,
        keys: &KeyMaterial,
    ) -> Result<String, EncryptionError>;
}
