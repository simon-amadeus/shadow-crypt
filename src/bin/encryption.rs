//! Binary for encrypting files with shadow-crypt.
//!
//! This binary provides the command-line interface for encrypting files using password-based
//! encryption with filename obfuscation.

use std::process;

use shadow_crypt_shell::{
    display_error,
    encryption::{
        cli::get_cli_args,
        file::EncryptionInput,
        validation::{ValidEncryptionArgs, validate_input},
        workflow::run_workflow,
    },
    errors::WorkflowError,
    memory::SecureString,
    password::resolve_encryption_password,
    ui::display_profiles,
    utils::resolve_output_dir,
};

fn run() -> Result<(), WorkflowError> {
    let args = get_cli_args(std::env::args().collect())?;
    if args.list_profiles {
        display_profiles();
        return Ok(());
    }

    let input: ValidEncryptionArgs = validate_input(args)?;
    let password: SecureString =
        resolve_encryption_password(input.password_file.as_deref(), &input.security_profile)?;
    let output_dir = resolve_output_dir(input.output_dir)?;
    let encryption_input = EncryptionInput::new(
        input.files,
        password,
        input.security_profile,
        output_dir,
        input.quiet,
        input.delete,
    );

    run_workflow(encryption_input)?;

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        display_error(&error);
        process::exit(error.exit_code());
    }
}
