//! Integration tests for --keep flag behavior across all CLI binaries

use std::process::Command;

#[test]
fn test_shadow_default_behavior() {
    let output = Command::new("./target/debug/shadow")
        .args(&["--quiet", "test.txt"])
        .output()
        .expect("Failed to execute shadow");
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    // Check the actual output message from the CLI
    assert!(stdout.contains("Source files will be removed"), 
        "Default behavior should remove source files");
}

#[test]
fn test_shadow_keep_flag() {
    let output = Command::new("./target/debug/shadow")
        .args(&["--quiet", "--keep", "test.txt"])
        .output()
        .expect("Failed to execute shadow");
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Source files will be preserved"), 
        "--keep flag should preserve source files");
}

#[test]
fn test_unshadow_default_behavior() {
    let output = Command::new("./target/debug/unshadow")
        .args(&["--quiet", "test.shadow"])
        .output()
        .expect("Failed to execute unshadow");
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Encrypted files will be removed after decryption"), 
        "Default behavior should remove encrypted files");
}

#[test]
fn test_unshadow_keep_flag() {
    let output = Command::new("./target/debug/unshadow")
        .args(&["--quiet", "--keep", "test.shadow"])
        .output()
        .expect("Failed to execute unshadow");
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Encrypted files will be preserved"), 
        "--keep flag should preserve encrypted files");
}


#[test]
fn test_shadows_no_keep_flag_needed() {
    // shadows doesn't modify files, so no --keep flag needed
    let output = Command::new("./target/debug/shadows")
        .args(&["--help"])
        .output()
        .expect("Failed to execute shadows");
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("--keep"), 
        "shadows shouldn't have --keep flag as it doesn't modify files");
}

#[test]
fn test_help_text_consistency() {
    // Test that help text matches actual implementation for shadow and unshadow
    let binaries = vec!["shadow", "unshadow"];
    
    for binary in binaries {
        let output = Command::new(&format!("./target/debug/{}", binary))
            .args(&["--help"])
            .output()
            .expect(&format!("Failed to execute {}", binary));
        
        let stdout = String::from_utf8(output.stdout).unwrap();
        
        // Check that help text mentions the keep flag correctly
        assert!(stdout.contains("Keep source files after successful") || (stdout.contains("Keep") && stdout.contains("(default: remove)")), 
            "{} help should mention keeping source files with default remove behavior", binary);
    }
}