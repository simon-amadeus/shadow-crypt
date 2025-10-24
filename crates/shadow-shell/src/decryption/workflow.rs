use rayon::prelude::*;
use shadow_core::{
    algorithm::Algorithm,
    memory::{SecureBytes, SecureKey, SecureString},
    progress::ProgressCounter,
    report::{DecryptionReport, KeyDerivationReport},
    v1::{
        crypt::decrypt_bytes_exposed,
        file::{EncryptedFile, PlaintextFile},
        header_ops::get_kdf_params,
        key::KeyDerivationParams,
        key_ops::derive_key,
    },
};

use crate::{
    decryption::{
        file::{DecryptionInput, DecryptionInputFile, DecryptionOutputFile},
        file_ops::{load_encrypted_file, store_plaintext_file},
    },
    errors::{WorkflowError, WorkflowResult},
    ui::{display_decryption_report, display_progress},
};

pub fn run_workflow(input: DecryptionInput) -> WorkflowResult<()> {
    let counter = ProgressCounter::new(input.files.len() as u64);

    // Process files in parallel using rayon
    input
        .files
        .par_iter()
        .map(|input_file| {
            counter.increment();
            display_progress(&counter);
            process_file_decryption(input_file.to_owned(), &input.password)
        })
        .for_each(display_decryption_report);

    Ok(())
}

fn process_file_decryption(
    file: DecryptionInputFile,
    password: &SecureString,
) -> WorkflowResult<DecryptionReport> {
    let start_time = std::time::Instant::now();

    let input_file: DecryptionInputFile = file;

    let encrypted_file: EncryptedFile = load_encrypted_file(&input_file)?;

    let filename_nonce: &[u8; 24] = &encrypted_file.header().filename_nonce;
    let filename_ciphertext: &[u8] = &encrypted_file.header().filename_ciphertext;

    let content_nonce: &[u8; 24] = &encrypted_file.header().content_nonce;
    let content_ciphertext: &[u8] = encrypted_file.ciphertext();

    let salt: &[u8; 16] = &encrypted_file.header().salt;
    let kdf_params: KeyDerivationParams = get_kdf_params(encrypted_file.header());
    let (key, _kdf_report): (SecureKey, KeyDerivationReport) =
        derive_key(password.as_str().as_bytes(), salt, &kdf_params)?;

    let (filename_bytes, algorithm): (Vec<u8>, Algorithm) =
        decrypt_bytes_exposed(filename_ciphertext, key.as_bytes(), filename_nonce)?;

    let filename = parse_string_from_bytes(&filename_bytes)?;

    let (content_bytes, _algorithm): (Vec<u8>, Algorithm) =
        decrypt_bytes_exposed(content_ciphertext, key.as_bytes(), content_nonce)?;

    let plaintext_file = PlaintextFile::new(filename.clone(), SecureBytes::new(content_bytes));
    let output_file: DecryptionOutputFile = store_plaintext_file(&plaintext_file)?;

    let duration = start_time.elapsed();

    Ok(DecryptionReport::new(
        input_file.filename,
        output_file.filename,
        duration,
        algorithm,
    ))
}

fn parse_string_from_bytes(bytes: &[u8]) -> WorkflowResult<String> {
    String::from_utf8(bytes.to_vec())
        .map_err(|_| WorkflowError::Decryption("Failed to decode string from bytes".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_string_from_bytes_valid() {
        let input_bytes = b"test_filename.txt";
        let result = parse_string_from_bytes(input_bytes).unwrap();
        assert_eq!(result, "test_filename.txt");
    }

    #[test]
    fn test_parse_string_from_bytes_invalid() {
        let input_bytes = vec![0xff, 0xfe, 0xfd]; // Invalid UTF-8 bytes
        let result = parse_string_from_bytes(&input_bytes);
        assert!(result.is_err());
        if let Err(WorkflowError::Decryption(msg)) = result {
            assert_eq!(msg, "Failed to decode string from bytes");
        } else {
            panic!("Expected Decryption error");
        }
    }
}
