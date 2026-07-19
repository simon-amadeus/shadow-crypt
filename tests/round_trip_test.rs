use shadow_crypt_shell::{
    SecurityProfile,
    decryption::{
        cli::DecryptionCliArgs, file::DecryptionInput,
        validation::validate_input as validate_decryption_input,
        workflow::run_workflow as run_decryption_workflow,
    },
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
fn test_encrypt_decrypt_round_trip() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let original_dir = std::env::current_dir().unwrap();

    // Change to temp directory for the test
    std::env::set_current_dir(&temp_dir).unwrap();

    let result: Result<(), Box<dyn std::error::Error>> = {
        let input_file = temp_dir.path().join("test.txt");

        // Create a test file
        let test_content = b"Hello, World! This is a test file.";
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

        // Find the encrypted file (it has a random name)
        let mut encrypted_file = None;
        for entry in fs::read_dir(&temp_dir).unwrap() {
            let entry = entry.unwrap();
            if let Some(ext) = entry.path().extension()
                && ext == "shadow"
            {
                encrypted_file = Some(entry.path());
                break;
            }
        }
        let encrypted_file = encrypted_file.expect("Encrypted file was not created");

        // Remove the original so decryption can restore it (no-overwrite policy)
        // and so the final comparison actually checks the decrypted output.
        fs::remove_file(&input_file).unwrap();

        // Create decryption CLI args
        let decrypt_cli_args = DecryptionCliArgs {
            input_files: vec![encrypted_file.to_str().unwrap().to_string()],
        };

        // Validate decryption input
        let valid_decrypt_args = validate_decryption_input(decrypt_cli_args).unwrap();

        // Create decryption input
        let decrypt_password = SecureString::new("testpassword".to_string());
        let decryption_input = DecryptionInput::new(
            valid_decrypt_args.files,
            decrypt_password,
            temp_dir.path().to_path_buf(),
        );

        // Run decryption
        run_decryption_workflow(decryption_input).unwrap();

        // Check that the decrypted file matches the original (it decrypts to the original filename)
        let decrypted_content = fs::read(&input_file).unwrap();
        assert_eq!(
            test_content.to_vec(),
            decrypted_content,
            "Decrypted content does not match original"
        );

        Ok(())
    };

    // Always restore original directory before temp_dir is dropped
    let _ = std::env::set_current_dir(original_dir);

    // Propagate any test failure
    result.unwrap();
}

#[test]
fn test_decrypt_with_wrong_password_reports_failure() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let temp_dir = TempDir::new().unwrap();

    let input_file = temp_dir.path().join("secret.txt");
    fs::write(&input_file, b"sensitive data").unwrap();

    let cli_args = EncryptionCliArgs {
        input_files: vec![input_file.to_str().unwrap().to_string()],
        test_mode: true,
    };
    let valid_args = validate_encryption_input(cli_args).unwrap();
    let encryption_input = EncryptionInput::new(
        valid_args.files,
        SecureString::new("correct password".to_string()),
        SecurityProfile::Test,
        temp_dir.path().to_path_buf(),
    );
    run_encryption_workflow(encryption_input).unwrap();

    let encrypted_file = fs::read_dir(&temp_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "shadow"))
        .expect("Encrypted file was not created");

    let decrypt_cli_args = DecryptionCliArgs {
        input_files: vec![encrypted_file.to_str().unwrap().to_string()],
    };
    let valid_decrypt_args = validate_decryption_input(decrypt_cli_args).unwrap();
    let decryption_input = DecryptionInput::new(
        valid_decrypt_args.files,
        SecureString::new("wrong password".to_string()),
        temp_dir.path().to_path_buf(),
    );

    // The workflow must surface per-file failures so the CLI exits nonzero.
    let result = run_decryption_workflow(decryption_input);
    assert!(result.is_err(), "wrong password should fail the workflow");
}
