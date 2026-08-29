mod common;

use std::fs;

use common::{TEST_PASSWORD, encrypt_files, find_shadow_files};
use shadow_crypt_shell::{
    listing::{file::ListingInput, workflow::run_workflow as run_listing_workflow},
    memory::SecureString,
};
use tempfile::TempDir;

#[test]
fn test_listing_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    fs::write(&file1, b"Content of file1").unwrap();
    fs::write(&file2, b"Content of file2").unwrap();

    encrypt_files(&[&file1, &file2], TEST_PASSWORD, temp_dir.path()).unwrap();
    assert_eq!(
        find_shadow_files(temp_dir.path()).len(),
        2,
        "Should have 2 shadow files"
    );

    // The listing workflow displays to the terminal, so there is no output to
    // assert on; check that it succeeds over a directory that contains both
    // shadow files and plaintext files.
    let listing_input = ListingInput::new(
        Some(SecureString::new(TEST_PASSWORD.to_string())),
        temp_dir.path().to_path_buf(),
        false,
    );
    run_listing_workflow(listing_input).unwrap();

    // Without a password the listing must still succeed, showing only the
    // plaintext header metadata.
    run_listing_workflow(ListingInput::new(
        None,
        temp_dir.path().to_path_buf(),
        false,
    ))
    .unwrap();
}
