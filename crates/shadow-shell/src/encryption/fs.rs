use std::{
    io::{Read, Write},
    path::PathBuf,
};

use rand::distr::{Alphabetic, SampleString};
use shadow_core::{
    memory::SecureBytes,
    v1::file::{EncryptedFile, PlaintextFile},
};

use crate::{
    encryption::{input::InputFile, output::OutputFile},
    errors::{WorkflowError, WorkflowResult},
};

pub fn store_encrypted_file(
    output_file: &OutputFile,
    encrypted_file: &EncryptedFile,
) -> WorkflowResult<()> {
    let mut f = std::fs::File::create(&output_file.path)?;
    let serialized_header: Vec<u8> =
        shadow_core::v1::header_ops::serialize(encrypted_file.header());
    f.write_all(&serialized_header)?;
    f.write_all(encrypted_file.ciphertext())?;

    Ok(())
}

pub fn load_file(file: &InputFile) -> WorkflowResult<PlaintextFile> {
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

fn generate_output_filename() -> WorkflowResult<String> {
    let mut rng = rand::rng();
    let len = 16;

    Ok(Alphabetic.sample_string(&mut rng, len))
}

pub fn create_output_file() -> WorkflowResult<OutputFile> {
    let filename = generate_output_filename()?;

    let mut path = PathBuf::from(&filename);
    path.set_extension("shadow");

    let filename = path
        .to_str()
        .ok_or_else(|| WorkflowError::File("Invalid output filename".to_string()))?
        .to_string();

    path = std::env::current_dir()?.join(path);

    Ok(OutputFile { path, filename })
}
