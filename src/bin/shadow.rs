use std::process;

use shadow_shell::{
    display_error,
    encryption::{
        cli::{ValidEncryptionInput, parse_args, validate_input},
        password::prompt_for_password_with_confirmation,
    },
    memory::SecureString,
};

fn main() {
    // Parse command line arguments
    let args = match parse_args() {
        Ok(args) => args,
        Err(error) => {
            display_error(error);
            process::exit(1);
        }
    };

    let input: ValidEncryptionInput = match validate_input(args) {
        Ok(input) => input,
        Err(error) => {
            display_error(error);
            process::exit(1);
        }
    };

    let _password: SecureString = match prompt_for_password_with_confirmation(input.weak_password) {
        Ok(pw) => pw,
        Err(error) => {
            display_error(error);
            process::exit(1);
        }
    };

    // Run encryption workflow
}
