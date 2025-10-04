use std::process::Command;

#[test]
fn test_unshadow_basic_functionality() {
    // Basic smoke test to ensure the binary was built correctly and shows proper help
    let help_output = Command::new("./target/debug/unshadow")
        .arg("--help")
        .current_dir(std::env::current_dir().unwrap())
        .output()
        .expect("Failed to execute unshadow command");
    
    assert!(help_output.status.success(), "Unshadow --help failed");
    
    let help_text = String::from_utf8(help_output.stdout).expect("Invalid UTF-8 in help output");
    assert!(help_text.contains("Decrypt .shadow files and restore original filenames"), 
        "Help text doesn't contain expected description");
    assert!(help_text.contains("--force"), "Help text doesn't contain --force flag");
    assert!(help_text.contains("--keep"), "Help text doesn't contain --keep flag");
    assert!(help_text.contains("--quiet"), "Help text doesn't contain --quiet flag");
}

#[test]
fn test_unshadow_validates_input() {
    // Test that unshadow properly validates input
    let output = Command::new("./target/debug/unshadow")
        .current_dir(std::env::current_dir().unwrap())
        .output()
        .expect("Failed to execute unshadow command");
    
    assert!(!output.status.success(), "Unshadow should fail without input files");
    
    let stderr = String::from_utf8(output.stderr).expect("Invalid UTF-8 in stderr");
    assert!(stderr.contains("At least one input"), 
        "Error message should mention missing input files");
}

#[test]
fn test_unshadow_binary_exists_and_runs() {
    // Basic smoke test to ensure the binary was built correctly
    let output = Command::new("./target/debug/unshadow")
        .arg("--version")
        .current_dir(std::env::current_dir().unwrap())
        .output()
        .expect("Failed to execute unshadow command");
    
    // Even if --version isn't implemented, the binary should at least exist and run
    // without crashing (status code might be non-zero but shouldn't panic)
    assert!(output.status.code().is_some(), "Unshadow binary crashed");
}