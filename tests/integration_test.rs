use shadow_core::memory::SecureBytes;
use shadow_core::v1::file_ops::get_encrypted_file_from_bytes;
use shadow_shell::{
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

    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
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
        let encryption_input =
            EncryptionInput::new(valid_args.files, password, SecurityProfile::Test);

        // Run encryption
        run_encryption_workflow(encryption_input).unwrap();

        // Find the encrypted file (it has a random name)
        let mut encrypted_file = None;
        for entry in fs::read_dir(&temp_dir).unwrap() {
            let entry = entry.unwrap();
            if let Some(ext) = entry.path().extension() {
                if ext == "shadow" {
                    encrypted_file = Some(entry.path());
                    break;
                }
            }
        }
        let encrypted_file = encrypted_file.expect("Encrypted file was not created");

        // Create decryption CLI args
        let decrypt_cli_args = DecryptionCliArgs {
            input_files: vec![encrypted_file.to_str().unwrap().to_string()],
        };

        // Validate decryption input
        let valid_decrypt_args = validate_decryption_input(decrypt_cli_args).unwrap();

        // Create decryption input
        let decrypt_password = SecureString::new("testpassword".to_string());
        let decryption_input = DecryptionInput::new(valid_decrypt_args.files, decrypt_password);

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
    })();

    // Always restore original directory before temp_dir is dropped
    let _ = std::env::set_current_dir(original_dir);

    // Propagate any test failure
    result.unwrap();
}

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
        let encryption_input =
            EncryptionInput::new(valid_args.files, password, SecurityProfile::Test);

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
        let secure_bytes = SecureBytes::new(encrypted_bytes);

        // Parse the encrypted file to get the header
        let encrypted_file = get_encrypted_file_from_bytes(&secure_bytes).unwrap();
        let header = encrypted_file.header();

        // The filename ciphertext should NOT be equal to the plaintext filename
        let original_filename = "sensitive_document.txt";
        let original_filename_bytes = original_filename.as_bytes();

        assert_ne!(
            header.filename_ciphertext.as_slice(),
            original_filename_bytes,
            "Filename is stored as plaintext in header, which violates security requirements"
        );

        // Also verify that the ciphertext is not empty and has reasonable length
        assert!(
            !header.filename_ciphertext.is_empty(),
            "Filename ciphertext is empty"
        );
        // XChaCha20Poly1305 adds 16 bytes of authentication tag
        assert!(
            header.filename_ciphertext.len() >= original_filename_bytes.len() + 16,
            "Filename ciphertext is suspiciously short: {} bytes for {} byte filename",
            header.filename_ciphertext.len(),
            original_filename_bytes.len()
        );

        Ok(())
    })();

    // Always restore original directory before temp_dir is dropped
    let _ = std::env::set_current_dir(original_dir);

    // Propagate any test failure
    result.unwrap();
}
