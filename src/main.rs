use crypto::cli::{App, print_banner, print_help};
use crypto::error::EncryptionError;
use std::env;

fn main() -> Result<(), EncryptionError> {
    // Check if help was requested
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 || args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print_banner();
        print_help();
        return Ok(());
    }

    // Show banner for interactive use
    if args.len() > 1 {
        print_banner();
    }

    // Run the application
    App::run()
}
