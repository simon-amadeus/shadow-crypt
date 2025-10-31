//! Binary for decrypting files encrypted with shadow-crypt.
//!
//! This binary provides the command-line interface for decrypting files that were encrypted
//! using shadow-crypt, restoring the original filenames and content.

use std::process;

use shadow_crypt_shell::{
    decryption::{
        cli::get_cli_args,
        file::DecryptionInput,
        validation::{ValidDecryptionArgs, validate_input},
        workflow::run_workflow,
    },
    display_error,
    errors::WorkflowError,
    memory::SecureString,
    password::prompt_for_password,
};

fn run() -> Result<(), WorkflowError> {
    let input: ValidDecryptionArgs =
        get_cli_args(std::env::args().collect()).and_then(validate_input)?;
    let password: SecureString = prompt_for_password()?;
    let output_dir = std::env::current_dir()?;

    run_workflow(DecryptionInput::new(input.files, password, output_dir))?;

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        display_error(error);
        process::exit(1);
    }
}
