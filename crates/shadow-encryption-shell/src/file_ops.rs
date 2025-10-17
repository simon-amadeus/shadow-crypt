// shadow-encryption-shell/src/file_ops.rs
// File I/O operations for encryption
// All functions have side effects - interact with file system

use shadow_core::{SecureString, SerializationError, hash_content, serialize_header};
use shadow_encryption_core::pipeline::{EncryptionError, create_encryption_request};
use shadow_encryption_core::{EncryptedFile, encrypt_file};
use shadow_shell::{ShellError, read_file_safely, write_file_atomically};
use std::fs;
use std::path::{Path, PathBuf};

/// Process a single file for encryption
/// Side effects: reads input file, writes output file, optionally deletes input
pub fn process_single_file(
    input_path: &Path,
    password: &SecureString,
    obfuscate_filename: bool,
    force: bool,
    keep: bool,
) -> Result<PathBuf, EncryptionFileError> {
    // 1. Read file content (I/O side effect)
    let content = read_file_safely(input_path)?;

    // 2. Extract filename
    let filename = input_path
        .file_name()
        .ok_or_else(|| EncryptionFileError::InvalidFilename(input_path.to_path_buf()))?
        .to_string_lossy()
        .to_string();

    // 3. Check for duplicate content (handles obfuscated files)
    if !force {
        let content_hash = hash_content(&content);
        let parent_dir = match input_path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let existing_hashes = scan_existing_shadow_files(parent_dir)?;
        if existing_hashes.contains(&content_hash) {
            return Err(EncryptionFileError::DuplicateContent {
                original_file: input_path.to_path_buf(),
                content_hash,
            });
        }
    }

    // 4. Create encryption request (pure function)
    let request = create_encryption_request(
        content,
        filename,
        password.clone(),
        obfuscate_filename,
        shadow_core::SecurityProfile::Production,
    );

    // 5. Encrypt file (pure function)
    let encrypted = encrypt_file(request)?;

    // 6. Determine output path
    let parent_dir = match input_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."), // Handle empty parent or None
    };
    let output_path = parent_dir.join(&encrypted.suggested_filename);

    // 7. Check for existing output file
    if output_path.exists() && !force {
        return Err(EncryptionFileError::OutputExists(output_path));
    }

    // 8. Write encrypted file (I/O side effect)
    write_encrypted_file(&encrypted, &output_path)?;

    // 9. Remove source file if not keeping (I/O side effect)
    if !keep {
        fs::remove_file(input_path)?;
    }

    Ok(output_path)
}

/// Write encrypted file to disk
/// Side effect: writes to file system
pub fn write_encrypted_file(
    encrypted: &EncryptedFile,
    output_path: &Path,
) -> Result<(), EncryptionFileError> {
    // Serialize header and combine with ciphertext
    let header_bytes = serialize_header(&encrypted.header)?;
    let mut file_data = header_bytes;
    file_data.extend_from_slice(&encrypted.ciphertext);

    // Write atomically using shell utility
    write_file_atomically(output_path, &file_data)?;

    Ok(())
}

/// Check for duplicate content by scanning existing .shadow files
/// Side effect: reads from file system
pub fn check_for_duplicate_content(
    input_paths: &[PathBuf],
    target_dir: &Path,
) -> Result<(), EncryptionFileError> {
    for input_path in input_paths {
        let content = read_file_safely(input_path)?;
        let content_hash = hash_content(&content);

        // Scan target directory for existing .shadow files
        let existing_hashes = scan_existing_shadow_files(target_dir)?;

        if existing_hashes.contains(&content_hash) {
            return Err(EncryptionFileError::DuplicateContent {
                original_file: input_path.clone(),
                content_hash,
            });
        }
    }

    Ok(())
}

/// Scan directory for existing .shadow files and extract their content hashes
/// Side effect: reads from file system
fn scan_existing_shadow_files(dir: &Path) -> Result<Vec<[u8; 32]>, EncryptionFileError> {
    let mut hashes = Vec::new();

    if !dir.exists() || !dir.is_dir() {
        return Ok(hashes);
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().map_or(false, |ext| ext == "shadow") {
            if let Ok(hash) = read_shadow_file_content_hash(&path) {
                hashes.push(hash);
            }
            // Ignore files we can't read - they might be corrupted or different format
        }
    }

    Ok(hashes)
}

/// Read content hash from a .shadow file header
/// Side effect: reads from file system
fn read_shadow_file_content_hash(path: &Path) -> Result<[u8; 32], EncryptionFileError> {
    use std::io::Read;

    let mut file = fs::File::open(path)?;
    let mut buffer = vec![0u8; 1024]; // Initial buffer for header

    // Read enough for basic header validation
    let bytes_read = file.read(&mut buffer)?;
    if bytes_read < 8 {
        return Err(EncryptionFileError::InvalidShadowFile(path.to_path_buf()));
    }

    // Check magic bytes
    if &buffer[0..8] != b"SHADOW01" {
        return Err(EncryptionFileError::InvalidShadowFile(path.to_path_buf()));
    }

    // Extract content hash (starts at offset 10: magic(8) + algorithm(1) + obfuscation(1))
    if bytes_read < 42 {
        // 10 + 32 for hash
        return Err(EncryptionFileError::InvalidShadowFile(path.to_path_buf()));
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&buffer[10..42]);
    Ok(hash)
}

/// Error type for encryption file operations
#[derive(Debug, thiserror::Error)]
pub enum EncryptionFileError {
    #[error("Shell error: {0}")]
    Shell(#[from] ShellError),

    #[error("Encryption error: {0}")]
    Encryption(#[from] EncryptionError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid filename: {0}")]
    InvalidFilename(PathBuf),

    #[error("Output file exists: {0}")]
    OutputExists(PathBuf),

    #[error("Duplicate content found for file: {original_file:?}")]
    DuplicateContent {
        original_file: PathBuf,
        content_hash: [u8; 32],
    },

    #[error("Invalid shadow file format: {0}")]
    InvalidShadowFile(PathBuf),
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadow_core::SecureString;
    use tempfile::TempDir;

    /// Fast test version of process_single_file using SecurityProfile::Test
    fn process_single_file_test(
        input_path: &Path,
        password: &SecureString,
        obfuscate_filename: bool,
        force: bool,
        keep: bool,
    ) -> Result<PathBuf, EncryptionFileError> {
        // 1. Read file content (I/O side effect)
        let content = read_file_safely(input_path)?;

        // 2. Extract filename
        let filename = input_path
            .file_name()
            .ok_or_else(|| EncryptionFileError::InvalidFilename(input_path.to_path_buf()))?
            .to_string_lossy()
            .to_string();

        // 3. Create encryption request with TEST parameters (pure function)
        let request = create_encryption_request(
            content,
            filename,
            password.clone(),
            obfuscate_filename,
            shadow_core::SecurityProfile::Test,
        );

        // 4. Encrypt file (pure function)
        let encrypted = encrypt_file(request)?;

        // 5. Determine output path
        let parent_dir = match input_path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."), // Handle empty parent or None
        };
        let output_path = parent_dir.join(&encrypted.suggested_filename);

        // 6. Check for existing output file
        if output_path.exists() && !force {
            return Err(EncryptionFileError::OutputExists(output_path));
        }

        // 7. Serialize and write the encrypted file (I/O side effect)
        let serialized_header = serialize_header(&encrypted.header)?;
        let mut file_content = Vec::new();
        file_content.extend_from_slice(&serialized_header);
        file_content.extend_from_slice(&encrypted.ciphertext);

        write_file_atomically(&output_path, &file_content)?;

        // 8. Optionally remove original file (I/O side effect)
        if !keep {
            std::fs::remove_file(input_path)?;
        }

        Ok(output_path)
    }

    #[test]
    fn test_process_single_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, b"test content").unwrap();

        let password = SecureString::new("correct horse battery staple".to_string());

        let result = process_single_file_test(
            &test_file, &password, false, // no obfuscation
            false, // no force
            true,  // keep original
        );

        assert!(result.is_ok());
        let output_path = result.unwrap();

        // Check output file exists
        assert!(output_path.exists());
        assert!(output_path.to_string_lossy().ends_with(".shadow"));

        // Check original file still exists (keep=true)
        assert!(test_file.exists());
    }

    #[test]
    fn test_process_single_file_remove_original() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, b"test content").unwrap();

        let password = SecureString::new("correct horse battery staple".to_string());

        let result = process_single_file_test(
            &test_file, &password, false, // no obfuscation
            false, // no force
            false, // don't keep original
        );

        assert!(result.is_ok());

        // Check original file was removed (keep=false)
        assert!(!test_file.exists());
    }

    #[test]
    fn test_output_exists_no_force() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        let output_file = temp_dir.path().join("test.txt.shadow");

        fs::write(&test_file, b"test content").unwrap();
        fs::write(&output_file, b"existing output").unwrap();

        let password = SecureString::new("correct horse battery staple".to_string());

        let result = process_single_file_test(
            &test_file, &password, false, // no obfuscation
            false, // no force
            true,  // keep original
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionFileError::OutputExists(_)
        ));
    }

    #[test]
    fn test_check_for_duplicate_content_no_duplicates() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, b"unique content").unwrap();

        let result = check_for_duplicate_content(&[test_file], temp_dir.path());
        assert!(result.is_ok());
    }
}
