use std::process;

use shadow_shell::{
    display_error,
    encryption::{
        cli::{parse_cli_args, validate_input},
        input::EncryptionInput,
        password::prompt_for_password_with_confirmation,
        workflow::run_workflow,
    },
    errors::WorkflowError,
    memory::SecureString,
};

fn run() -> Result<(), WorkflowError> {
    let args = parse_cli_args()?;
    let input = validate_input(args)?;
    let password: SecureString = prompt_for_password_with_confirmation(input.weak_password)?;
    let request = EncryptionInput::new(input.files, password);
    run_workflow(request)?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        display_error(error);
        process::exit(1);
    }
}
