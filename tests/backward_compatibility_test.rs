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

/// Decrypts a committed fixture file and checks filename and content.
/// Guards against changes that would break decryption of existing files.
fn assert_fixture_decrypts(fixture_name: &str, expected_filename: &str, expected_content: &[u8]) {
    let temp_dir = TempDir::new().unwrap();

    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(fixture_name);
    assert!(fixture.exists(), "Fixture not found at {:?}", fixture);

    let temp_shadow_file = temp_dir.path().join(fixture_name);
    fs::copy(&fixture, &temp_shadow_file).unwrap();

    let decrypt_cli_args = DecryptionCliArgs {
        input_files: vec![temp_shadow_file.to_str().unwrap().to_string()],
    };
    let valid_decrypt_args = validate_decryption_input(decrypt_cli_args).unwrap();

    let decrypt_password = SecureString::new("testpassword".to_string()); // DO NOT CHANGE THIS PASSWORD
    let decryption_input = DecryptionInput::new(
        valid_decrypt_args.files,
        decrypt_password,
        temp_dir.path().to_path_buf(),
    );

    run_decryption_workflow(decryption_input).unwrap();

    let decrypted_file = temp_dir.path().join(expected_filename);
    assert!(decrypted_file.exists(), "Decrypted file was not created");

    let decrypted_content = fs::read(&decrypted_file).unwrap();
    assert_eq!(
        decrypted_content, expected_content,
        "Decrypted content does not match expected content"
    );
}

#[test]
fn test_v2_backward_compatibility() {
    let _lock = TEST_MUTEX.lock().unwrap();
    assert_fixture_decrypts(
        "test_v2.shadow",
        "test_v2_plaintext.txt",
        b"This is a test file for v2 backward compatibility testing. It contains known content that should be decrypted correctly.\n",
    );
}

/// Regenerates the v2 fixture. Run manually after an intentional format
/// change: `cargo test regenerate_v2_fixture -- --ignored`
#[test]
#[ignore]
fn regenerate_v2_fixture() {
    use shadow_crypt_shell::{
        SecurityProfile,
        encryption::{
            cli::CliArgs as EncryptionCliArgs, file::EncryptionInput,
            validation::validate_input as validate_encryption_input,
            workflow::run_workflow as run_encryption_workflow,
        },
    };

    let _lock = TEST_MUTEX.lock().unwrap();
    let temp_dir = TempDir::new().unwrap();

    let input_file = temp_dir.path().join("test_v2_plaintext.txt");
    fs::write(
        &input_file,
        b"This is a test file for v2 backward compatibility testing. It contains known content that should be decrypted correctly.\n",
    )
    .unwrap();

    let cli_args = EncryptionCliArgs {
        input_files: vec![input_file.to_str().unwrap().to_string()],
        test_mode: true,
    };
    let valid_args = validate_encryption_input(cli_args).unwrap();
    let encryption_input = EncryptionInput::new(
        valid_args.files,
        SecureString::new("testpassword".to_string()), // DO NOT CHANGE THIS PASSWORD
        SecurityProfile::Test,
        temp_dir.path().to_path_buf(),
    );
    run_encryption_workflow(encryption_input).unwrap();

    let encrypted = fs::read_dir(&temp_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "shadow"))
        .expect("Encrypted file was not created");

    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("test_v2.shadow");
    fs::copy(&encrypted, &fixture).unwrap();
}

#[test]
fn test_v1_backward_compatibility() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let original_dir = std::env::current_dir().unwrap();

    // Change to temp directory for the test
    std::env::set_current_dir(&temp_dir).unwrap();

    let result: Result<(), Box<dyn std::error::Error>> = {
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
    };

    // Always restore original directory before temp_dir is dropped
    let _ = std::env::set_current_dir(original_dir);

    // Propagate any test failure
    result.unwrap();
}
