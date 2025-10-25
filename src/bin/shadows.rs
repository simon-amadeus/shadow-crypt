use std::process;

use shadow_crypt_shell::{
    display_error,
    errors::WorkflowError,
    listing::{file::ListingInput, workflow::run_workflow},
    memory::SecureString,
    password::prompt_for_password,
};

fn run() -> Result<(), WorkflowError> {
    let work_dir = std::env::current_dir()?;
    let password: SecureString = prompt_for_password()?;
    let input = ListingInput::new(password, work_dir);

    run_workflow(input)?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        display_error(error);
        process::exit(1);
    }
}
