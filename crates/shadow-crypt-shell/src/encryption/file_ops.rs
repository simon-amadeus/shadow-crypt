use std::{
    io::{Read, Write},
    path::PathBuf,
};

use rand::rand_core::{OsRng, TryRngCore};
use shadow_crypt_core::{
    file::PlaintextFile,
    memory::{SecureBytes, SecureString},
    v2::file::EncryptedFile,
};

use crate::{
    encryption::file::{EncryptionInputFile, EncryptionOutputFile},
    errors::{WorkflowError, WorkflowResult},
};

pub fn store_encrypted_file(
    encrypted_file: &EncryptedFile,
    output_dir: &std::path::Path,
) -> WorkflowResult<EncryptionOutputFile> {
    let (mut f, output_file) = create_encryption_output_file(output_dir)?;
    f.write_all(&encrypted_file.to_bytes())?;

    Ok(output_file)
}

pub fn load_plaintext_file(file: &EncryptionInputFile) -> WorkflowResult<PlaintextFile> {
    let filename = SecureString::new(file.filename.clone());
    let size: usize = file.size as usize;

    let mut f = std::fs::File::open(&file.path)?;
    let mut buffer: Vec<u8> = Vec::with_capacity(size);

    f.read_to_end(&mut buffer)?;

    let content = SecureBytes::new(buffer);

    Ok(PlaintextFile::new(filename, content))
}

fn generate_output_filename() -> WorkflowResult<String> {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const NAME_LENGTH: usize = 16;
    // Largest multiple of CHARSET.len() that fits in a byte; rejection
    // sampling below this bound keeps every character equally likely.
    const REJECTION_BOUND: u8 = (u8::MAX / CHARSET.len() as u8) * CHARSET.len() as u8;

    let mut name = String::with_capacity(NAME_LENGTH);
    let mut bytes = [0u8; 2 * NAME_LENGTH];
    while name.len() < NAME_LENGTH {
        OsRng.try_fill_bytes(&mut bytes).map_err(|e| {
            WorkflowError::File(format!("Failed to generate output filename: {}", e))
        })?;
        for byte in bytes {
            if byte < REJECTION_BOUND && name.len() < NAME_LENGTH {
                name.push(CHARSET[byte as usize % CHARSET.len()] as char);
            }
        }
    }
    Ok(name)
}

fn create_encryption_output_file(
    output_dir: &std::path::Path,
) -> WorkflowResult<(std::fs::File, EncryptionOutputFile)> {
    // create_new claims the filename atomically, so concurrent encryptions
    // can never race each other (or an attacker) into overwriting a file.
    for _ in 0..1000 {
        let mut path = PathBuf::from(generate_output_filename()?);
        path.set_extension("shadow");

        let full_path = output_dir.join(&path);

        match std::fs::File::create_new(&full_path) {
            Ok(f) => {
                let filename_str = path
                    .to_str()
                    .ok_or_else(|| WorkflowError::File("Invalid output filename".to_string()))?
                    .to_string();

                return Ok((
                    f,
                    EncryptionOutputFile {
                        path: full_path,
                        filename: filename_str,
                    },
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }

    Err(WorkflowError::File(
        "Unable to generate a unique output filename after 1000 attempts".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadow_crypt_core::{
        profile::SecurityProfile,
        v2::{file::EncryptedFile, header::FileHeader, key::KeyDerivationParams},
    };
    use std::fs;
    use tempfile::TempDir;

    fn create_test_header() -> FileHeader {
        let salt = [1u8; 16];
        let kdf_params = KeyDerivationParams::from(SecurityProfile::Test);
        let content_nonce = [2u8; 24];
        let filename_nonce = [3u8; 24];
        let filename_ciphertext = vec![4, 5, 6, 7, 8];

        FileHeader::new(
            salt,
            kdf_params,
            content_nonce,
            filename_nonce,
            filename_ciphertext,
        )
        .unwrap()
    }

    fn create_test_encrypted_file() -> EncryptedFile {
        let header = create_test_header();
        let ciphertext = vec![10, 11, 12, 13, 14];
        EncryptedFile::new(header, ciphertext)
    }

    #[test]
    fn test_generate_output_filename() {
        let filename = generate_output_filename().unwrap();
        assert_eq!(filename.len(), 16);
        assert!(filename.chars().all(|c| c.is_ascii_alphabetic()));
    }

    #[test]
    fn test_create_encryption_output_file() {
        let temp_dir = TempDir::new().unwrap();

        let (_, first) = create_encryption_output_file(temp_dir.path()).unwrap();
        let (_, second) = create_encryption_output_file(temp_dir.path()).unwrap();

        assert!(first.path.exists());
        assert!(second.path.exists());
        assert_ne!(first.filename, second.filename);
        assert!(first.filename.ends_with(".shadow"));
    }

    #[test]
    fn test_load_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_content = b"Hello, World!";
        let test_filename = "test.txt";
        let file_path = temp_dir.path().join(test_filename);

        // Create test file
        fs::write(&file_path, test_content).unwrap();

        let input_file = EncryptionInputFile {
            path: file_path.clone(),
            filename: test_filename.to_string(),
            size: test_content.len() as u64,
        };

        let plaintext_file = load_plaintext_file(&input_file).unwrap();

        assert_eq!(plaintext_file.filename().as_str(), test_filename);
        assert_eq!(plaintext_file.content().as_slice(), test_content);
    }

    #[test]
    fn test_store_encrypted_file() {
        // Create temp directory for isolated testing
        let temp_dir = TempDir::new().unwrap();

        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            let encrypted_file = create_test_encrypted_file();
            let output_file = store_encrypted_file(&encrypted_file, temp_dir.path())?;

            // Check file was created in temp directory
            assert!(output_file.path.exists());

            // Canonicalize paths to handle macOS /private symlink
            let canonical_output = fs::canonicalize(&output_file.path)?;
            let canonical_temp = fs::canonicalize(temp_dir.path())?;
            assert!(canonical_output.starts_with(canonical_temp));

            // Read back and verify content
            let written_content = fs::read(&output_file.path)?;
            assert_eq!(written_content, encrypted_file.to_bytes());
            Ok(())
        })();

        // Propagate any test failure
        result.unwrap();
    }
}
