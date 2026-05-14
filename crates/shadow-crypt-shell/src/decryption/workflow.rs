use rayon::prelude::*;
use shadow_crypt_core::{
    algorithm::Algorithm,
    memory::{SecureBytes, SecureKey, SecureString},
    progress::ProgressCounter,
    report::{DecryptionReport, KeyDerivationReport},
    v1::{
        crypt::decrypt_bytes,
        file::{EncryptedFile, PlaintextFile},
        header_ops::get_kdf_params,
        key::KeyDerivationParams,
        key_ops::derive_key,
    },
};

// Upper bounds for KDF parameters read from untrusted file headers.
// These prevent a crafted file from causing OOM or excessive CPU use.
const MAX_KDF_MEMORY_KIB: u32 = 8 * 1024 * 1024; // 8 GiB
const MAX_KDF_ITERATIONS: u32 = 1_000;
const MAX_KDF_PARALLELISM: u32 = 256;
const MAX_KDF_KEY_SIZE: u8 = 64;

use crate::{
    decryption::{
        file::{DecryptionInput, DecryptionInputFile, DecryptionOutputFile},
        file_ops::{load_encrypted_file, store_plaintext_file},
    },
    errors::WorkflowResult,
    ui::{display_decryption_report, display_progress},
    utils::parse_string_from_bytes,
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
            process_file_decryption(input_file.to_owned(), &input.password, &input.output_dir)
        })
        .for_each(display_decryption_report);

    Ok(())
}

fn validate_kdf_params(params: &KeyDerivationParams) -> WorkflowResult<()> {
    if params.memory_cost > MAX_KDF_MEMORY_KIB {
        return Err(crate::errors::WorkflowError::UserInput(format!(
            "KDF memory cost in file header is too large: {} KiB (max {} KiB)",
            params.memory_cost, MAX_KDF_MEMORY_KIB
        )));
    }
    if params.time_cost > MAX_KDF_ITERATIONS {
        return Err(crate::errors::WorkflowError::UserInput(format!(
            "KDF iteration count in file header is too large: {} (max {})",
            params.time_cost, MAX_KDF_ITERATIONS
        )));
    }
    if params.parallelism > MAX_KDF_PARALLELISM {
        return Err(crate::errors::WorkflowError::UserInput(format!(
            "KDF parallelism in file header is too large: {} (max {})",
            params.parallelism, MAX_KDF_PARALLELISM
        )));
    }
    if params.key_size > MAX_KDF_KEY_SIZE {
        return Err(crate::errors::WorkflowError::UserInput(format!(
            "KDF key size in file header is too large: {} bytes (max {})",
            params.key_size, MAX_KDF_KEY_SIZE
        )));
    }
    Ok(())
}

fn process_file_decryption(
    file: DecryptionInputFile,
    password: &SecureString,
    output_dir: &std::path::Path,
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
    validate_kdf_params(&kdf_params)?;
    let (key, _kdf_report): (SecureKey, KeyDerivationReport) =
        derive_key(password.as_str().as_bytes(), salt, &kdf_params)?;

    let (filename_bytes, algorithm): (SecureBytes, Algorithm) =
        decrypt_bytes(filename_ciphertext, key.as_bytes(), filename_nonce)?;

    let filename: SecureString = parse_string_from_bytes(&filename_bytes)?;

    let (content_bytes, _algorithm): (SecureBytes, Algorithm) =
        decrypt_bytes(content_ciphertext, key.as_bytes(), content_nonce)?;

    let plaintext_file = PlaintextFile::new(filename.clone(), content_bytes);
    let output_file: DecryptionOutputFile = store_plaintext_file(&plaintext_file, output_dir)?;

    let duration = start_time.elapsed();

    Ok(DecryptionReport::new(
        input_file.filename,
        output_file.filename,
        duration,
        algorithm,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_params() -> KeyDerivationParams {
        KeyDerivationParams::new(1024, 1, 1, 32)
    }

    #[test]
    fn test_valid_kdf_params_accepted() {
        assert!(validate_kdf_params(&valid_params()).is_ok());
    }

    #[test]
    fn test_memory_cost_too_large() {
        let params = KeyDerivationParams::new(MAX_KDF_MEMORY_KIB + 1, 1, 1, 32);
        assert!(validate_kdf_params(&params).is_err());
    }

    #[test]
    fn test_memory_cost_at_limit_accepted() {
        let params = KeyDerivationParams::new(MAX_KDF_MEMORY_KIB, 1, 1, 32);
        assert!(validate_kdf_params(&params).is_ok());
    }

    #[test]
    fn test_iterations_too_large() {
        let params = KeyDerivationParams::new(1024, MAX_KDF_ITERATIONS + 1, 1, 32);
        assert!(validate_kdf_params(&params).is_err());
    }

    #[test]
    fn test_parallelism_too_large() {
        let params = KeyDerivationParams::new(1024, 1, MAX_KDF_PARALLELISM + 1, 32);
        assert!(validate_kdf_params(&params).is_err());
    }

    #[test]
    fn test_key_size_too_large() {
        let params = KeyDerivationParams::new(1024, 1, 1, MAX_KDF_KEY_SIZE + 1);
        assert!(validate_kdf_params(&params).is_err());
    }

    #[test]
    fn test_production_params_accepted() {
        let params = KeyDerivationParams::production_defaults();
        assert!(validate_kdf_params(&params).is_ok());
    }
}
