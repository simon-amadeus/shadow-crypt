use rayon::prelude::*;
use shadow_crypt_core::{
    memory::SecureString,
    progress::ProgressCounter,
    report::EncryptionReport,
    v3::{self, key::KeyDerivationParams, stream::StreamSealer},
};

use crate::{
    encryption::{
        file::{EncryptionInput, EncryptionInputFile},
        file_ops::{gather_metadata, stream_encrypt_file},
        nonce::{generate_nonce, generate_nonce_prefix},
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
            )
            .map_err(|e| WorkflowError::Encryption(format!("'{}': {}", input_file.filename, e)));
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
        kdf_params.derive_key(password.as_str().as_bytes(), salt.as_ref())
    })?;

    let nonce_prefix: [u8; 16] = generate_nonce_prefix()?;
    let metadata_nonce: [u8; 24] = generate_nonce()?;
    let metadata = gather_metadata(&file);

    let (header, sealer) = StreamSealer::begin(
        &metadata,
        &key,
        kdf_params.clone(),
        salt,
        nonce_prefix,
        metadata_nonce,
    )?;
    let output_file = stream_encrypt_file(&file, &header, sealer, output_dir)?;

    let duration = start_time.elapsed();

    Ok(EncryptionReport::new(
        file.filename,
        output_file.filename,
        duration,
        v3::ALGORITHM,
    ))
}
