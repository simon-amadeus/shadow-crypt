use std::process;

use shadow_shell::{
    display_error,
    encryption::cli::{ValidEncryptionInput, parse_args, validate_input},
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

    let _input: ValidEncryptionInput = match validate_input(args) {
        Ok(input) => input,
        Err(error) => {
            display_error(error);
            process::exit(1);
        }
    };

    // Run encryption workflow
}
