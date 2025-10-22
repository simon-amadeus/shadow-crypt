use shadow_core::memory::SecureString;

use crate::{encryption::cli::EncryptableFile, errors::WorkflowResult};


pub struct EncryptionRequest {
    pub files: Vec<EncryptableFile>,
    pub password: SecureString,
}
impl EncryptionRequest {
    pub fn new(files: Vec<EncryptableFile>, password: SecureString) -> Self {
        Self { files, password }
    }
}


pub fn run_workflow(request: EncryptionRequest) -> WorkflowResult<()> {
    // Placeholder for the main encryption workflow logic
    // This function would coordinate file I/O, user interaction, and progress display

    // 1. generate salt <- io
    // 2. derive key from password <- io

    // for each file
        // 3. generate filename nonce <- io
        // 4. load file content <- io
        // 5. encrypt filename <- deterministic
        // 6. generate content nonce <- io
        // 7. encrypt content <- deterministic
        // 8. create header <- deterministic
        // 9. create encrypted file structure <- deterministic
        // 10. store encrypted file <- io


    Ok(())
}