use std::process;

use shadow_shell::{
    display_error, errors::WorkflowError, memory::SecureString, password::prompt_for_password,
};

fn run() -> Result<(), WorkflowError> {
    let work_dir = std::env::current_dir()?;
    let password: SecureString = prompt_for_password()?;

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        display_error(error);
        process::exit(1);
    }
}
