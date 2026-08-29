//! Binary for listing files encrypted with shadow-crypt.
//!
//! This binary provides the command-line interface for listing encrypted
//! files with their decrypted original filenames (requires the password).
//! With `--no-names` it lists only the obfuscated names and plaintext header
//! metadata, needing no password.

use std::process;

use shadow_crypt_shell::{
    display_error,
    errors::WorkflowError,
    listing::{cli::get_cli_args, file::ListingInput, workflow::run_workflow},
    memory::SecureString,
    password::resolve_password,
};

fn run() -> Result<(), WorkflowError> {
    let args = get_cli_args(std::env::args().collect())?;
    let work_dir = match args.dir {
        Some(dir) => dir,
        None => std::env::current_dir()?,
    };

    // Only decrypting original filenames needs a password; --no-names reads
    // plaintext header metadata without any key derivation.
    let password: Option<SecureString> = if args.no_names {
        None
    } else {
        Some(resolve_password(args.password_file.as_deref())?)
    };

    run_workflow(ListingInput::new(password, work_dir, args.json))?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        display_error(&error);
        process::exit(error.exit_code());
    }
}
