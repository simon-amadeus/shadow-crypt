use shadow_crypt_shell::{
    SecurityProfile,
    encryption::{
        cli::CliArgs as EncryptionCliArgs, file::EncryptionInput,
        validation::validate_input as validate_encryption_input,
        workflow::run_workflow as run_encryption_workflow,
    },
    memory::SecureString,
};
use std::fs;
use std::sync::Mutex;
use tempfile::TempDir;

static TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_filename_is_encrypted_in_header() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let original_dir = std::env::current_dir().unwrap();

    // Change to temp directory for the test
    std::env::set_current_dir(&temp_dir).unwrap();

    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let input_file = temp_dir.path().join("sensitive_document.txt");

        // Create a test file
        let test_content = b"This is sensitive content.";
        fs::write(&input_file, test_content).unwrap();

        // Create CLI args
        let cli_args = EncryptionCliArgs {
            input_files: vec![input_file.to_str().unwrap().to_string()],
            test_mode: true,
        };

        // Validate input
        let valid_args = validate_encryption_input(cli_args).unwrap();

        // Create encryption input
        let password = SecureString::new("testpassword".to_string());
        let encryption_input = EncryptionInput::new(
            valid_args.files,
            password,
            SecurityProfile::Test,
            temp_dir.path().to_path_buf(),
        );

        // Run encryption
        run_encryption_workflow(encryption_input).unwrap();

        // Find the encrypted file
        let mut encrypted_file_path = None;
        for entry in fs::read_dir(&temp_dir).unwrap() {
            let entry = entry.unwrap();
            if let Some(ext) = entry.path().extension() {
                if ext == "shadow" {
                    encrypted_file_path = Some(entry.path());
                    break;
                }
            }
        }
        let encrypted_file_path = encrypted_file_path.expect("Encrypted file was not created");

        // Read the encrypted file
        let encrypted_bytes = fs::read(&encrypted_file_path).unwrap();

        // The filename should NOT be stored as plaintext in the encrypted file
        let original_filename = "sensitive_document.txt";
        let original_filename_bytes = original_filename.as_bytes();

        assert!(
            !encrypted_bytes
                .windows(original_filename_bytes.len())
                .any(|window| window == original_filename_bytes),
            "Filename appears to be stored as plaintext in the encrypted file, which violates security requirements"
        );

        // Also verify that the file has some content (not empty)
        assert!(!encrypted_bytes.is_empty(), "Encrypted file is empty");

        Ok(())
    })();

    // Always restore original directory before temp_dir is dropped
    let _ = std::env::set_current_dir(original_dir);

    // Propagate any test failure
    result.unwrap();
}

#[test]
fn test_content_is_encrypted_in_file() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let original_dir = std::env::current_dir().unwrap();

    // Change to temp directory for the test
    std::env::set_current_dir(&temp_dir).unwrap();

    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let input_file = temp_dir.path().join("secret.txt");

        // Create a test file with distinctive content
        let test_content =
            b"This is highly confidential information that should never appear in plaintext.";
        fs::write(&input_file, test_content).unwrap();

        // Create CLI args
        let cli_args = EncryptionCliArgs {
            input_files: vec![input_file.to_str().unwrap().to_string()],
            test_mode: true,
        };

        // Validate input
        let valid_args = validate_encryption_input(cli_args).unwrap();

        // Create encryption input
        let password = SecureString::new("testpassword".to_string());
        let encryption_input = EncryptionInput::new(
            valid_args.files,
            password,
            SecurityProfile::Test,
            temp_dir.path().to_path_buf(),
        );

        // Run encryption
        run_encryption_workflow(encryption_input).unwrap();

        // Find the encrypted file
        let mut encrypted_file_path = None;
        for entry in fs::read_dir(&temp_dir).unwrap() {
            let entry = entry.unwrap();
            if let Some(ext) = entry.path().extension() {
                if ext == "shadow" {
                    encrypted_file_path = Some(entry.path());
                    break;
                }
            }
        }
        let encrypted_file_path = encrypted_file_path.expect("Encrypted file was not created");

        // Read the encrypted file
        let encrypted_bytes = fs::read(&encrypted_file_path).unwrap();

        // The original content should NOT be stored as plaintext in the encrypted file
        assert!(
            !encrypted_bytes
                .windows(test_content.len())
                .any(|window| window == test_content),
            "Original content appears to be stored as plaintext in the encrypted file, which violates security requirements"
        );

        // Also verify that the file has some content (not empty)
        assert!(!encrypted_bytes.is_empty(), "Encrypted file is empty");

        Ok(())
    })();

    // Always restore original directory before temp_dir is dropped
    let _ = std::env::set_current_dir(original_dir);

    // Propagate any test failure
    result.unwrap();
}
