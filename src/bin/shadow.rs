use std::process;

use shadow_shell::{
    display_error, encryption::{
        cli::{parse_cli_args, validate_input, ValidEncryptionInput},
        password::prompt_for_password_with_confirmation, workflow::{run_workflow, EncryptionRequest},
    }, errors::WorkflowError, memory::SecureString
};

fn run() -> Result<(), WorkflowError> {
    let args = parse_cli_args()?;
    let input: ValidEncryptionInput = validate_input(args)?;
    let password: SecureString = prompt_for_password_with_confirmation(input.weak_password)?;
    let request = EncryptionRequest::new(input.files, password);
    run_workflow(request)?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        display_error(error);
        process::exit(1);
    }
}