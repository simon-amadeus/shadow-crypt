use rayon::prelude::*;
use shadow_core::{
    memory::SecureKey,
    v1::{
        encryption::encrypt_bytes,
        file::{EncryptedFile, PlaintextFile},
        header::FileHeader,
        key::KeyDerivationParams,
    },
};

use crate::{
    encryption::{
        fs::{create_output_file, load_file, store_encrypted_file},
        input::{EncryptionInput, InputFile},
        nonce::generate_nonce,
        output::{EncryptionReport, OutputFile},
        salt::generate_salt,
    },
    errors::WorkflowResult,
    key::derive_key,
    progress::ProgressCounter,
    ui::display_report,
};

pub fn run_workflow(input: EncryptionInput) -> WorkflowResult<()> {
    let salt: [u8; 16] = generate_salt()?;

    let params = KeyDerivationParams::production_defaults();
    let key: SecureKey = derive_key(input.password.as_str().as_bytes(), salt.as_ref(), &params)?;

    let counter = ProgressCounter::new(input.files.len() as u64);

    // Process files in parallel using Rayon
    input
        .files
        .par_iter()
        .map(|input_file| {
            process_file_encryption(input_file.to_owned(), &key, &salt, &params, &counter)
        })
        .for_each(display_report);

    Ok(())
}

fn process_file_encryption(
    file: InputFile,
    key: &SecureKey,
    salt: &[u8; 16],
    kdf_params: &KeyDerivationParams,
    counter: &ProgressCounter,
) -> WorkflowResult<EncryptionReport> {
    let start_time = std::time::Instant::now();
    counter.increment();

    let input_file: InputFile = file;
    let output_file: OutputFile = create_output_file()?;

    let filename_nonce: [u8; 24] = generate_nonce()?;
    let content_nonce: [u8; 24] = generate_nonce()?;
    let plaintext_file: PlaintextFile = load_file(&input_file)?;

    let filename_ciphertext: Vec<u8> = encrypt_bytes(
        input_file.filename.as_bytes(),
        key.as_bytes(),
        &filename_nonce,
    )?;

    let content_ciphertext: Vec<u8> = encrypt_bytes(
        plaintext_file.content().as_slice(),
        key.as_bytes(),
        &content_nonce,
    )?;

    let header = FileHeader::new(
        salt.clone(),
        kdf_params.clone(),
        content_nonce,
        filename_nonce,
        filename_ciphertext,
    );

    let encrypted_file = EncryptedFile::new(header, content_ciphertext);

    store_encrypted_file(&output_file, &encrypted_file)?;

    let duration = start_time.elapsed();

    Ok(EncryptionReport::new(
        input_file.filename,
        output_file.filename,
        duration,
    ))
}
