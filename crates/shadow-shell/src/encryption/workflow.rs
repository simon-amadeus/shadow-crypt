use shadow_core::{encryption::input::EncryptionInput, v1::key::KeyDerivationParams};

use crate::{encryption::salt::generate_salt, errors::WorkflowResult, key::derive_key};

pub fn run_workflow(input: EncryptionInput) -> WorkflowResult<()> {
    let salt: [u8; 16] = generate_salt()?;

    let params = KeyDerivationParams::production_defaults();
    let _key: [u8; 32] = derive_key(input.password.as_str().as_bytes(), salt.as_ref(), &params)?;

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
