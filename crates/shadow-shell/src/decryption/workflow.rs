use rayon::prelude::*;
use shadow_core::{
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
