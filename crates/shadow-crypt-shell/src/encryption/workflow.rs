use rayon::prelude::*;
use shadow_crypt_core::{
    algorithm::Algorithm,
    memory::SecureString,
    progress::ProgressCounter,
    report::EncryptionReport,
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
        file::{EncryptionInput, EncryptionInputFile},
        file_ops::{load_plaintext_file, store_encrypted_file},
        nonce::generate_nonce,
        salt::generate_salt,
    },
    errors::{WorkflowError, WorkflowResult},
    kdf::with_kdf_memory_permit,
    ui::{display_encryption_report, display_progress},
};

pub fn run_workflow(input: EncryptionInput) -> WorkflowResult<()> {
    let params = KeyDerivationParams::from(input.security_profile);
    let total = input.files.len();
    let counter = ProgressCounter::new(total as u64);

    // Each file gets its own salt and derived key so that files encrypted in the
    // same session cannot be correlated by comparing header salts.
    let failures: usize = input
        .files
        .par_iter()
        .map(|input_file| {
            let result = process_file_encryption(
                input_file.to_owned(),
                &input.password,
                &params,
                &input.output_dir,
            );
            counter.increment();
            display_progress(&counter);
            let failed = result.is_err();
            display_encryption_report(result);
            usize::from(failed)
        })
        .sum();

    if failures > 0 {
        return Err(WorkflowError::Encryption(format!(
            "{} of {} file(s) failed to encrypt",
            failures, total
        )));
    }

    Ok(())
}

fn process_file_encryption(
    file: EncryptionInputFile,
    password: &SecureString,
    kdf_params: &KeyDerivationParams,
    output_dir: &std::path::Path,
) -> WorkflowResult<EncryptionReport> {
    let start_time = std::time::Instant::now();

    let salt: [u8; 16] = generate_salt()?;
    let (key, _) = with_kdf_memory_permit(kdf_params.memory_cost, || {
        derive_key(password.as_str().as_bytes(), salt.as_ref(), kdf_params)
    })?;

    let filename_nonce: [u8; 24] = generate_nonce()?;
    let content_nonce: [u8; 24] = generate_nonce()?;
    let plaintext_file: PlaintextFile = load_plaintext_file(&file)?;

    let (filename_ciphertext, _): (Vec<u8>, Algorithm) =
        encrypt_bytes(file.filename.as_bytes(), key.as_bytes(), &filename_nonce)?;

    let (content_ciphertext, algorithm): (Vec<u8>, Algorithm) = encrypt_bytes(
        plaintext_file.content().as_slice(),
        key.as_bytes(),
        &content_nonce,
    )?;

    let header = FileHeader::new(
        salt,
        kdf_params.clone(),
        content_nonce,
        filename_nonce,
        filename_ciphertext,
    );

    let encrypted_file = EncryptedFile::new(header, content_ciphertext);
    let output_file = store_encrypted_file(&encrypted_file, output_dir)?;

    let duration = start_time.elapsed();

    Ok(EncryptionReport::new(
        file.filename,
        output_file.filename,
        duration,
        algorithm,
    ))
}
