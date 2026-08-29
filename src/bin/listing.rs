//! Binary for listing files encrypted with shadow-crypt.
//!
//! This binary provides the command-line interface for listing encrypted files,
//! displaying their obfuscated names and metadata. With `--names` it also
//! decrypts and shows the original filenames, which requires the password.

use std::process;

use shadow_crypt_shell::{
    display_error,
    errors::WorkflowError,
    listing::{cli::get_cli_args, file::ListingInput, workflow::run_workflow},
    memory::SecureString,
    password::prompt_for_password,
};

fn run() -> Result<(), WorkflowError> {
    let args = get_cli_args(std::env::args().collect())?;
    let work_dir = match args.dir {
        Some(dir) => dir,
        None => std::env::current_dir()?,
    };

    // Only decrypting original filenames needs a password; the default
    // listing reads plaintext header metadata without any key derivation.
    let password: Option<SecureString> = if args.names {
        Some(prompt_for_password()?)
    } else {
        None
    };

    run_workflow(ListingInput::new(password, work_dir))?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        display_error(error);
        process::exit(1);
    }
}
