//! Shadow migration tool
//! 
//! This tool provides file format migration capabilities for Shadow encrypted files.
//! It can analyze files for migration needs and will support migrating between
//! different versions of the Shadow file format as new versions are released.

use shadow_crypt::migration::run_migration_cli;

fn main() {
    run_migration_cli();
}