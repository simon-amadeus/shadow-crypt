use rayon::prelude::*;
use shadow_crypt_core::{
    algorithm::Algorithm,
    memory::SecureKey,
    progress::ProgressCounter,
    report::{EncryptionReport, KeyDerivationReport},
    v1::{
        crypt::encrypt_bytes,
        file::{EncryptedFile, PlaintextFile},
        header::FileHeader,
        key::KeyDerivationParams,
        key_ops::derive_key,
    },
};

use crate::{
    encryption::{
        file::{EncryptionInput, EncryptionInputFile, EncryptionOutputFile},
        file_ops::{load_plaintext_file, store_encrypted_file},
        nonce::generate_nonce,
        salt::generate_salt,
    },
    errors::WorkflowResult,
    ui::{display_encryption_report, display_key_derivation_report, display_progress},
};

pub fn run_workflow(input: EncryptionInput) -> WorkflowResult<()> {
    let salt: [u8; 16] = generate_salt()?;

    let params = KeyDerivationParams::from(input.security_profile);
    let (key, report): (SecureKey, KeyDerivationReport) =
        derive_key(input.password.as_str().as_bytes(), salt.as_ref(), &params)?;

    display_key_derivation_report(&report);

    let counter = ProgressCounter::new(input.files.len() as u64);

    // Process files in parallel using rayon
    input
        .files
        .par_iter()
        .map(|input_file| {
            counter.increment();
            display_progress(&counter);
            process_file_encryption(
                input_file.to_owned(),
                &key,
                &salt,
                &params,
                &input.output_dir,
            )
        })
        .for_each(display_encryption_report);

    Ok(())
}

fn process_file_encryption(
    file: EncryptionInputFile,
    key: &SecureKey,
    salt: &[u8; 16],
    kdf_params: &KeyDerivationParams,
    output_dir: &std::path::Path,
) -> WorkflowResult<EncryptionReport> {
    let start_time = std::time::Instant::now();

    let input_file: EncryptionInputFile = file;

    let filename_nonce: [u8; 24] = generate_nonce()?;
    let content_nonce: [u8; 24] = generate_nonce()?;
    let plaintext_file: PlaintextFile = load_plaintext_file(&input_file)?;

    let (filename_ciphertext, _): (Vec<u8>, Algorithm) = encrypt_bytes(
        input_file.filename.as_bytes(),
        key.as_bytes(),
        &filename_nonce,
    )?;

    let (content_ciphertext, algorithm): (Vec<u8>, Algorithm) = encrypt_bytes(
        plaintext_file.content().as_slice(),
        key.as_bytes(),
        &content_nonce,
    )?;

    let header = FileHeader::new(
        *salt,
        kdf_params.clone(),
        content_nonce,
        filename_nonce,
        filename_ciphertext,
    );

    let encrypted_file = EncryptedFile::new(header, content_ciphertext);

    let output_file: EncryptionOutputFile = store_encrypted_file(&encrypted_file, output_dir)?;

    let duration = start_time.elapsed();

    Ok(EncryptionReport::new(
        input_file.filename,
        output_file.filename,
        duration,
        algorithm,
    ))
}
