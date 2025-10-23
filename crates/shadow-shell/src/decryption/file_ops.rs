use std::io::{Read, Write};

use shadow_core::{
    memory::SecureBytes,
    v1::{
        file::{EncryptedFile, PlaintextFile},
        file_ops::get_encrypted_file_from_bytes,
    },
};

use crate::{
    encryption::file::{InputFile, OutputFile},
    errors::WorkflowResult,
};

pub fn read_n_bytes_from_file(path: &std::path::Path, n: usize) -> WorkflowResult<SecureBytes> {
    let f = std::fs::File::open(path)?;
    let mut buffer: Vec<u8> = Vec::with_capacity(n);
    f.take(n as u64).read_to_end(&mut buffer)?;

    Ok(SecureBytes::new(buffer))
}

pub fn store_plaintext_file(file: &PlaintextFile) -> WorkflowResult<OutputFile> {
    let output_file = OutputFile {
        path: std::env::current_dir()?.join(file.filename()),
        filename: file.filename().to_string(),
    };

    let mut f = std::fs::File::create(output_file.path.as_path())?;
    f.write_all(file.content().as_slice())?;

    Ok(output_file)
}

pub fn load_encrypted_file(file: &InputFile) -> WorkflowResult<EncryptedFile> {
    let size: usize = file.size as usize;

    let mut f = std::fs::File::open(&file.path)?;
    let mut buffer: Vec<u8> = Vec::with_capacity(size);

    f.read_to_end(&mut buffer)?;

    let content = SecureBytes::new(buffer.clone());

    use zeroize::Zeroize;
    buffer.zeroize(); // Clear the temporary buffer

    Ok(get_encrypted_file_from_bytes(&content)?)
}
