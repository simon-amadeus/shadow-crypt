use std::process;

use shadow_shell::{
    SecurityProfile, display_error,
    encryption::{
        cli::{get_security_profile, parse_cli_args},
        file::EncryptionInput,
        password::prompt_for_password_with_confirmation,
        validation::{ValidEncryptionArgs, validate_input},
        workflow::run_workflow,
    },
    errors::WorkflowError,
    memory::SecureString,
};

fn run() -> Result<(), WorkflowError> {
    let input: ValidEncryptionArgs = parse_cli_args().and_then(validate_input)?;
    let security_profile: SecurityProfile = get_security_profile(input.test_mode);
    let password: SecureString = prompt_for_password_with_confirmation(&security_profile)?;
    let encryption_input = EncryptionInput::new(input.files, password, security_profile);

    run_workflow(encryption_input)?;

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        display_error(error);
        process::exit(1);
    }
}
