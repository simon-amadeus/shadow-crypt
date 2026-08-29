use rayon::prelude::*;
use shadow_crypt_core::{
    memory::SecureString,
    progress::ProgressCounter,
    report::EncryptionReport,
    v3::{self, key::KeyDerivationParams, stream::StreamSealer},
};

use crate::{
    encryption::{
        file::{EncryptionInput, EncryptionInputFile, InputKind},
        file_ops::{
            gather_metadata, stream_encrypt_directory, stream_encrypt_file, walk_directory,
        },
        nonce::{generate_nonce, generate_nonce_prefix},
        salt::generate_salt,
    },
    errors::{WorkflowError, WorkflowResult},
    kdf::with_kdf_memory_permit,
    ui::{display_encryption_success, display_error, display_progress, display_warning},
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
                input.delete,
            )
            .map_err(|e| WorkflowError::per_file(&input_file.filename, e));
            counter.increment();
            if !input.quiet {
                display_progress(&counter);
            }
            match result {
                Ok(report) => {
                    if !input.quiet {
                        display_encryption_success(&report);
                    }
                    0
                }
                Err(e) => {
                    display_error(&e);
                    1
                }
            }
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
    delete_original: bool,
) -> WorkflowResult<EncryptionReport> {
    let start_time = std::time::Instant::now();

    let salt: [u8; 16] = generate_salt()?;
    let (key, _) = with_kdf_memory_permit(kdf_params.memory_cost, || {
        kdf_params.derive_key(password.as_str().as_bytes(), salt.as_ref())
    })?;

    let nonce_prefix: [u8; 16] = generate_nonce_prefix()?;
    let metadata_nonce: [u8; 24] = generate_nonce()?;

    let output_file = match file.kind {
        InputKind::File => {
            let metadata = gather_metadata(&file);
            let (header, sealer) = StreamSealer::begin(
                &metadata,
                &key,
                kdf_params.clone(),
                salt,
                nonce_prefix,
                metadata_nonce,
            )?;
            stream_encrypt_file(&file, &header, sealer, output_dir)?
        }
        InputKind::Directory => {
            let (entries, skipped) = walk_directory(&file.path)?;
            if skipped > 0 {
                display_warning(&format!(
                    "Skipped {} unsupported entr{} (symlinks, special files) in '{}'",
                    skipped,
                    if skipped == 1 { "y" } else { "ies" },
                    file.filename
                ));
            }
            let metadata = gather_metadata(&file).into_archive();
            let (header, sealer) = StreamSealer::begin(
                &metadata,
                &key,
                kdf_params.clone(),
                salt,
                nonce_prefix,
                metadata_nonce,
            )?;
            stream_encrypt_directory(&entries, &header, sealer, output_dir)?
        }
    };

    // Delete only after the output is fully committed to disk. A failed
    // deletion is an error (scripts relying on --delete must notice), but
    // the encrypted output itself is complete and valid at this point.
    if delete_original {
        let removal = match file.kind {
            InputKind::File => std::fs::remove_file(&file.path),
            InputKind::Directory => std::fs::remove_dir_all(&file.path),
        };
        removal.map_err(|e| {
            WorkflowError::File(format!(
                "encrypted successfully to '{}', but failed to delete the original: {}",
                output_file.filename, e
            ))
        })?;
    }

    let duration = start_time.elapsed();

    Ok(EncryptionReport::new(
        file.filename,
        output_file.filename,
        duration,
        v3::ALGORITHM,
        delete_original,
    ))
}
