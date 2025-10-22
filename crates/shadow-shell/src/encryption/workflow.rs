use std::{io::Read, path::PathBuf};

use rand::Rng;
use shadow_core::{
    memory::SecureBytes,
    v1::{
        file::{self, EncryptedFile, PlaintextFile},
        key::KeyDerivationParams,
    },
};

use crate::{
    encryption::{
        input::{EncryptionInput, InputFile, OutputFile},
        nonce::generate_nonce,
        salt::generate_salt,
    },
    errors::WorkflowResult,
    key::derive_key,
};

pub fn run_workflow(input: EncryptionInput) -> WorkflowResult<()> {
    // 1. generate salt
    let salt: [u8; 16] = generate_salt()?;

    // 2. generate key derivation params
    let params = KeyDerivationParams::production_defaults();

    // 3. derive key
    let _key: [u8; 32] = derive_key(input.password.as_str().as_bytes(), salt.as_ref(), &params)?;

    // for each file in input.files
    // 4. generate filename nonce <- io
    // 5. load file content <- io
    // 6. encrypt filename <- deterministic
    // 7. generate content nonce <- io
    // 8. encrypt content <- deterministic
    // 9. create header <- deterministic
    // 10. create encrypted file structure <- deterministic
    // 11. store encrypted file <- io

    use rayon::prelude::*;
    let _results: Vec<WorkflowResult<()>> = input.files.par_iter().map(process_file).collect();

    Ok(())
}

fn process_file(file: &InputFile) -> WorkflowResult<()> {
    // Placeholder for file processing logic
    println!("Processing file: {}", file.filename);

    let input_filename = file.filename.clone();
    let output_filename = generate_random_filename()?;
    let output_file = create_output_file()?;

    let filename_nonce: [u8; 24] = generate_nonce()?;
    let content_nonce: [u8; 24] = generate_nonce()?;
    let plaintext_file: PlaintextFile = load_file(file)?;

    Ok(())
}

fn load_file(file: &InputFile) -> WorkflowResult<PlaintextFile> {
    let filename = file.filename.clone();
    let size: usize = file.size as usize;

    let mut f = std::fs::File::open(&file.path)?;
    let mut buffer: Vec<u8> = Vec::with_capacity(size);

    f.read_to_end(&mut buffer)?;

    let content = SecureBytes::new(buffer.clone());

    use zeroize::Zeroize;
    buffer.zeroize(); // Clear the temporary buffer

    Ok(PlaintextFile::new(filename, content))
}

fn generate_random_filename() -> WorkflowResult<String> {
    let mut rng = rand::rng();
    let range = rand::distr::Alphabetic;

    Ok(rng.sample(range).to_string())
}

fn create_output_file() -> WorkflowResult<OutputFile> {
    let filename = generate_random_filename()?;
    let mut path = PathBuf::from(&filename);

    path.set_extension("shadow");
    path = std::env::current_dir()?.join(path);

    Ok(OutputFile { path, filename })
}

struct EncryptionResult {
    ciphertext: Vec<u8>,
    authentication_tag: [u8; 16],
}
