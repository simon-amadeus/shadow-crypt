//! Integration tests for --keep flag behavior across all CLI binaries

use std::process::Command;

#[test]
fn test_shadow_default_behavior() {
    let output = Command::new("./target/debug/shadow")
        .args(&["--quiet", "test.txt"])
        .output()
        .expect("Failed to execute shadow");
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("removed after encryption"), 
        "Default behavior should remove source files");
}

#[test]
fn test_shadow_keep_flag() {
    let output = Command::new("./target/debug/shadow")
        .args(&["--quiet", "--keep", "test.txt"])
        .output()
        .expect("Failed to execute shadow");
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("preserved"), 
        "--keep flag should preserve source files");
}

#[test]
fn test_unshadow_default_behavior() {
    let output = Command::new("./target/debug/unshadow")
        .args(&["--quiet", "test.shadow"])
        .output()
        .expect("Failed to execute unshadow");
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("removed after decryption"), 
        "Default behavior should remove encrypted files");
}

#[test]
fn test_unshadow_keep_flag() {
    let output = Command::new("./target/debug/unshadow")
        .args(&["--quiet", "--keep", "test.shadow"])
        .output()
        .expect("Failed to execute unshadow");
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("preserved"), 
        "--keep flag should preserve encrypted files");
}

#[test]
fn test_shadowmigrate_default_behavior() {
    let output = Command::new("./target/debug/shadowmigrate")
        .args(&["--quiet", "test.shadow"])
        .output()
        .expect("Failed to execute shadowmigrate");
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("removed after migration"), 
        "Default behavior should remove original files");
}

#[test]
fn test_shadowmigrate_keep_flag() {
    let output = Command::new("./target/debug/shadowmigrate")
        .args(&["--quiet", "--keep", "test.shadow"])
        .output()
        .expect("Failed to execute shadowmigrate");
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("preserved"), 
        "--keep flag should preserve original files");
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
    // Test that help text matches specification
    let binaries = vec!["shadow", "unshadow", "shadowmigrate"];
    
    for binary in binaries {
        let output = Command::new(&format!("./target/debug/{}", binary))
            .args(&["--help"])
            .output()
            .expect(&format!("Failed to execute {}", binary));
        
        let stdout = String::from_utf8(output.stdout).unwrap();
        
        if binary != "shadows" {  // shadows doesn't modify files
            assert!(stdout.contains("Keep source files after successful"), 
                "{} help should mention keeping source files", binary);
            assert!(stdout.contains("(default: remove)"), 
                "{} help should specify default is to remove", binary);
        }
    }
}