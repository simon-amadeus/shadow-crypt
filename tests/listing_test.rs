use shadow_crypt_shell::{
    SecurityProfile,
    encryption::{
        cli::CliArgs as EncryptionCliArgs, file::EncryptionInput,
        validation::validate_input as validate_encryption_input,
        workflow::run_workflow as run_encryption_workflow,
    },
    listing::{file::ListingInput, workflow::run_workflow as run_listing_workflow},
    memory::SecureString,
};
use std::fs;
use std::sync::Mutex;
use tempfile::TempDir;

static TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_listing_workflow() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let original_dir = std::env::current_dir().unwrap();

    // Change to temp directory for the test
    std::env::set_current_dir(&temp_dir).unwrap();

    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        // Create test files
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");
        fs::write(&file1, b"Content of file1").unwrap();
        fs::write(&file2, b"Content of file2").unwrap();

        // Encrypt files
        let cli_args = EncryptionCliArgs {
            input_files: vec![
                file1.to_str().unwrap().to_string(),
                file2.to_str().unwrap().to_string(),
            ],
            test_mode: true,
        };

        let valid_args = validate_encryption_input(cli_args).unwrap();
        let password = SecureString::new("testpassword".to_string());
        let encryption_input = EncryptionInput::new(
            valid_args.files,
            password.clone(),
            SecurityProfile::Test,
            temp_dir.path().to_path_buf(),
        );

        run_encryption_workflow(encryption_input).unwrap();

        // Now list the shadow files
        let listing_input = ListingInput::new(password, temp_dir.path().to_path_buf());
        run_listing_workflow(listing_input).unwrap();

        // Since the workflow displays to UI, we can't easily check the output,
        // but we can check that it doesn't error and that shadow files exist
        let mut shadow_files = vec![];
        for entry in fs::read_dir(&temp_dir).unwrap() {
            let entry = entry.unwrap();
            if let Some(ext) = entry.path().extension() {
                if ext == "shadow" {
                    shadow_files.push(entry.path());
                }
            }
        }
        assert_eq!(shadow_files.len(), 2, "Should have 2 shadow files");

        Ok(())
    })();

    // Always restore original directory before temp_dir is dropped
    let _ = std::env::set_current_dir(original_dir);

    // Propagate any test failure
    result.unwrap();
}
