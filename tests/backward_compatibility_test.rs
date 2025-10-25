use shadow_crypt_shell::{
    decryption::{
        cli::DecryptionCliArgs, file::DecryptionInput,
        validation::validate_input as validate_decryption_input,
        workflow::run_workflow as run_decryption_workflow,
    },
    memory::SecureString,
};
use std::fs;
use std::sync::Mutex;
use tempfile::TempDir;

static TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_v1_backward_compatibility() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let original_dir = std::env::current_dir().unwrap();

    // Change to temp directory for the test
    std::env::set_current_dir(&temp_dir).unwrap();

    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        // Copy the test v1 encrypted file to temp directory
        let test_shadow_file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("test_v1.shadow");

        if !test_shadow_file.exists() {
            panic!("Test V1 encrypted file not found at {:?}", test_shadow_file);
        }

        let temp_shadow_file = temp_dir.path().join("test_v1.shadow");
        fs::copy(&test_shadow_file, &temp_shadow_file).unwrap();

        // Create decryption CLI args
        let decrypt_cli_args = DecryptionCliArgs {
            input_files: vec![temp_shadow_file.to_str().unwrap().to_string()],
        };

        // Validate decryption input
        let valid_decrypt_args = validate_decryption_input(decrypt_cli_args).unwrap();

        // Create decryption input with the hardcoded password
        let decrypt_password = SecureString::new("testpassword".to_string()); // DO NOT CHANGE THIS PASSWORD
        let decryption_input = DecryptionInput::new(
            valid_decrypt_args.files,
            decrypt_password,
            temp_dir.path().to_path_buf(),
        );

        // Run decryption
        run_decryption_workflow(decryption_input).unwrap();

        // Check that the decrypted file exists and has the expected content
        let expected_filename = "test_v1_plaintext.txt";
        let decrypted_file = temp_dir.path().join(expected_filename);
        assert!(decrypted_file.exists(), "Decrypted file was not created");

        let decrypted_content = fs::read(&decrypted_file).unwrap();
        let expected_content = b"This is a test file for backward compatibility testing. It contains known content that should be decrypted correctly.\n";

        assert_eq!(
            decrypted_content, expected_content,
            "Decrypted content does not match expected content"
        );

        Ok(())
    })();

    // Always restore original directory before temp_dir is dropped
    let _ = std::env::set_current_dir(original_dir);

    // Propagate any test failure
    result.unwrap();
}
