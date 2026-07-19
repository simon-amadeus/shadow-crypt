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

use crate::{
    decryption::{
        file::{DecryptionInput, DecryptionInputFile, DecryptionOutputFile},
        file_ops::{load_encrypted_file, store_plaintext_file},
    },
    errors::WorkflowResult,
    kdf::validate_untrusted_kdf_params,
    ui::{display_decryption_report, display_progress},
    utils::parse_string_from_bytes,
};

pub fn run_workflow(input: DecryptionInput) -> WorkflowResult<()> {
    let total = input.files.len();
    let counter = ProgressCounter::new(total as u64);

    // Process files in parallel using rayon
    let failures: usize = input
        .files
        .par_iter()
        .map(|input_file| {
            let result =
                process_file_decryption(input_file.to_owned(), &input.password, &input.output_dir);
            counter.increment();
            display_progress(&counter);
            let failed = result.is_err();
            display_decryption_report(result);
            usize::from(failed)
        })
        .sum();

    if failures > 0 {
        return Err(crate::errors::WorkflowError::Decryption(format!(
            "{} of {} file(s) failed to decrypt",
            failures, total
        )));
    }

    Ok(())
}

fn validate_kdf_params(params: &KeyDerivationParams) -> WorkflowResult<()> {
    validate_untrusted_kdf_params(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        params.key_size,
    )
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
    use crate::kdf::MAX_KDF_MEMORY_KIB;

    #[test]
    fn test_valid_kdf_params_accepted() {
        assert!(validate_kdf_params(&KeyDerivationParams::new(1024, 1, 1, 32)).is_ok());
    }

    #[test]
    fn test_oversized_kdf_params_rejected() {
        let params = KeyDerivationParams::new(MAX_KDF_MEMORY_KIB + 1, 1, 1, 32);
        assert!(validate_kdf_params(&params).is_err());
    }
}
