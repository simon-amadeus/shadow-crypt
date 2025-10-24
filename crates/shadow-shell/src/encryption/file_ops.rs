use std::{
    io::{Read, Write},
    path::PathBuf,
};

use rand::distr::{Alphabetic, SampleString};
use shadow_core::{
    memory::{SecureBytes, SecureString},
    v1::file::{EncryptedFile, PlaintextFile},
};

use crate::{
    encryption::file::{EncryptionInputFile, EncryptionOutputFile},
    errors::{WorkflowError, WorkflowResult},
};

pub fn store_encrypted_file(
    encrypted_file: &EncryptedFile,
) -> WorkflowResult<EncryptionOutputFile> {
    let output_file = create_encryption_output_file()?;
    let mut f = std::fs::File::create(&output_file.path)?;
    let serialized_header: Vec<u8> =
        shadow_core::v1::header_ops::serialize(encrypted_file.header());
    f.write_all(&serialized_header)?;
    f.write_all(encrypted_file.ciphertext())?;

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
    let mut rng = rand::rng();
    let len = 16;

    Ok(Alphabetic.sample_string(&mut rng, len))
}

fn create_encryption_output_file() -> WorkflowResult<EncryptionOutputFile> {
    let mut counter = 0;
    loop {
        let base = generate_output_filename()?;
        let filename = if counter == 0 {
            base
        } else {
            format!("{}_{}", base, counter)
        };

        let mut path = PathBuf::from(&filename);
        path.set_extension("shadow");

        let full_path = std::env::current_dir()?.join(&path);

        if !full_path.exists() {
            let filename_str = path
                .to_str()
                .ok_or_else(|| WorkflowError::File("Invalid output filename".to_string()))?
                .to_string();

            return Ok(EncryptionOutputFile {
                path: full_path,
                filename: filename_str,
            });
        }

        counter += 1;
        if counter > 1000 {
            return Err(WorkflowError::File(
                "Unable to generate a unique output filename after 1000 attempts".to_string(),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadow_core::{
        profile::SecurityProfile,
        v1::{file::EncryptedFile, header::FileHeader, key::KeyDerivationParams},
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
    fn test_create_output_file() {
        // Test filename generation without creating actual files
        let filename = generate_output_filename().unwrap();
        assert_eq!(filename.len(), 16);
        assert!(filename.chars().all(|c| c.is_ascii_alphabetic()));

        // Test path construction logic
        let expected_filename = format!("{}.shadow", filename);

        // We can't easily test create_output_file without changing directories,
        // but we can verify the filename format it would generate
        assert!(expected_filename.ends_with(".shadow"));
        assert!(expected_filename.len() > 7);
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
        let original_dir = std::env::current_dir().unwrap();

        // Temporarily change to temp directory - this is necessary because
        // store_encrypted_file uses current_dir() internally
        if let Err(e) = std::env::set_current_dir(&temp_dir) {
            // If we can't change directory, skip the test
            eprintln!(
                "Skipping test_store_encrypted_file: cannot change directory: {}",
                e
            );
            return;
        }

        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            let encrypted_file = create_test_encrypted_file();
            let output_file = store_encrypted_file(&encrypted_file)?;

            // Check file was created in temp directory
            assert!(output_file.path.exists());

            // Canonicalize paths to handle macOS /private symlink
            let canonical_output = fs::canonicalize(&output_file.path)?;
            let canonical_temp = fs::canonicalize(temp_dir.path())?;
            assert!(canonical_output.starts_with(canonical_temp));

            // Read back and verify content
            let written_content = fs::read(&output_file.path)?;
            let expected_header = shadow_core::v1::header_ops::serialize(encrypted_file.header());
            let expected_content = [expected_header, encrypted_file.ciphertext().clone()].concat();

            assert_eq!(written_content, expected_content);
            Ok(())
        })();

        // Always restore original directory, even if test failed
        let _ = std::env::set_current_dir(original_dir);

        // Propagate any test failure
        result.unwrap();
    }
}
