//! # Shadow Main Binary
//!
//! Default binary entry point (shadow).

use shadow_crypt::cli::shadow;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    shadow::run()
}