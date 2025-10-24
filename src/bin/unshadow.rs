use std::process;

use shadow_shell::{
    decryption::{
        cli::get_cli_args,
        file::DecryptionInput,
        password::prompt_for_password,
        validation::{ValidDecryptionArgs, validate_input},
        workflow::run_workflow,
    },
    display_error,
    errors::WorkflowError,
    memory::SecureString,
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
