//! Integration tests for repository interfaces
//! 
//! Tests both mock and standard implementations of file and password repositories.

use shadow_crypt::domain::repositories::{
    FileRepository, PasswordRepository, FileType, PasswordStrength,
    MockFileRepository, MockPasswordRepository
};
use shadow_crypt::infrastructure::StandardFileRepository;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_mock_file_repository_basic_operations() {
    let mut mock_repo = MockFileRepository::new();
    
    // Test file doesn't exist initially
    assert!(!mock_repo.file_exists(Path::new("/test/file.txt")));
    
    // Add a file and test operations
    let test_content = b"Hello, World!";
    mock_repo.add_file("/test/file.txt", test_content.to_vec());
    
    // Test file exists now
    assert!(mock_repo.file_exists(Path::new("/test/file.txt")));
    
    // Test reading
    let content = mock_repo.read_file(Path::new("/test/file.txt")).unwrap();
    assert_eq!(content, test_content);
    
    // Test metadata
    let metadata = mock_repo.file_metadata(Path::new("/test/file.txt")).unwrap();
    assert_eq!(metadata.original_filename, "file.txt");
    assert_eq!(metadata.file_size, test_content.len() as u64);
    assert_eq!(metadata.file_type, FileType::Regular);
    
    // Verify operations were tracked
    let operations = mock_repo.operations();
    assert!(operations.len() >= 3);
}

#[test] 
fn test_mock_file_repository_failure_simulation() {
    let mut mock_repo = MockFileRepository::new();
    mock_repo.set_should_fail(true, "Simulated failure");
    
    // All operations should fail
    assert!(mock_repo.read_file(Path::new("/test.txt")).is_err());
    assert!(mock_repo.write_file(Path::new("/test.txt"), b"data").is_err());
    assert!(mock_repo.file_metadata(Path::new("/test.txt")).is_err());
}

#[test]
fn test_standard_file_repository_basic_operations() {
    let repo = StandardFileRepository::new();
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    let test_content = b"Hello, World!";
    
    // Test file doesn't exist initially
    assert!(!repo.file_exists(&test_file));
    
    // Test write
    repo.write_file(&test_file, test_content).unwrap();
    assert!(repo.file_exists(&test_file));
    
    // Test read
    let content = repo.read_file(&test_file).unwrap();
    assert_eq!(content, test_content);
    
    // Test metadata
    let metadata = repo.file_metadata(&test_file).unwrap();
    assert_eq!(metadata.original_filename, "test.txt");
    assert_eq!(metadata.file_size, test_content.len() as u64);
    assert_eq!(metadata.file_type, FileType::Regular);
}

#[test]
fn test_standard_file_repository_atomic_write() {
    let repo = StandardFileRepository::new();
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("atomic_test.txt");
    let test_content = b"Atomic write test content";
    
    // Test atomic write
    repo.write_file_atomic(&test_file, test_content).unwrap();
    assert!(repo.file_exists(&test_file));
    
    // Verify content is correct
    let content = repo.read_file(&test_file).unwrap();
    assert_eq!(content, test_content);
    
    // Ensure no .tmp file remains
    let temp_file = test_file.with_extension("tmp");
    assert!(!repo.file_exists(&temp_file));
}

#[test]
fn test_standard_file_repository_secure_delete() {
    let repo = StandardFileRepository::new();
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("delete_test.txt");
    let test_content = b"This file will be securely deleted";
    
    // Create file
    repo.write_file(&test_file, test_content).unwrap();
    assert!(repo.file_exists(&test_file));
    
    // Secure delete
    repo.delete_file_secure(&test_file).unwrap();
    assert!(!repo.file_exists(&test_file));
}

#[test]
fn test_mock_password_repository_basic() {
    let mut mock_repo = MockPasswordRepository::new();
    mock_repo.set_password_responses(vec![
        "test_password".to_string(),
        "confirmed_password".to_string(),
        "confirmed_password".to_string(),
    ]);
    
    // Test basic password prompt
    let password = mock_repo.prompt_password("Enter password: ").unwrap();
    assert_eq!(password, "test_password");
    
    // Test password confirmation (should get same password twice)
    let confirmed = mock_repo.prompt_password_with_confirmation("Enter password: ").unwrap();
    assert_eq!(confirmed, "confirmed_password");
}

#[test]
fn test_mock_password_repository_confirmation_mismatch() {
    let mut mock_repo = MockPasswordRepository::new();
    mock_repo.set_password_responses(vec![
        "password1".to_string(),
        "password2".to_string(),
    ]);
    
    // Should fail due to mismatch
    let result = mock_repo.prompt_password_with_confirmation("Enter password: ");
    assert!(result.is_err());
}

#[test]
fn test_password_strength_validation() {
    let repo = MockPasswordRepository::new();
    
    // Test weak password
    let weak = repo.validate_password_strength("123");
    assert!(matches!(weak, PasswordStrength::Weak { .. }));
    assert!(!weak.is_acceptable());
    
    // Test moderate password (meets basic requirements)
    let moderate = repo.validate_password_strength("MySecret1");
    assert!(matches!(moderate, PasswordStrength::Moderate));
    assert!(moderate.is_acceptable());
    
    // Test strong password  
    let strong = repo.validate_password_strength("MyStr0ng!P@ssw0rd");
    assert!(matches!(strong, PasswordStrength::Strong));
    assert!(strong.is_acceptable());
    
    // Test password with common patterns
    let common = repo.validate_password_strength("password123");
    if let PasswordStrength::Weak { issues } = common {
        assert!(issues.iter().any(|issue| issue.contains("password")));
    }
}

#[test]
fn test_password_strength_descriptions() {
    let repo = MockPasswordRepository::new();
    
    let weak = repo.validate_password_strength("123");
    assert!(weak.description().contains("Weak password"));
    
    let moderate = repo.validate_password_strength("MySecret1");
    assert!(moderate.description().contains("Moderate"));
    
    let strong = repo.validate_password_strength("MyStr0ng!P@ssw0rd");
    assert!(strong.description().contains("Strong"));
}

#[test]
fn test_file_repository_error_handling() {
    let repo = StandardFileRepository::new();
    
    // Test reading non-existent file
    let result = repo.read_file(Path::new("/nonexistent/file.txt"));
    assert!(result.is_err());
    
    // Test getting metadata for non-existent file
    let result = repo.file_metadata(Path::new("/nonexistent/file.txt"));
    assert!(result.is_err());
    
    // Test deleting non-existent file
    let result = repo.delete_file_secure(Path::new("/nonexistent/file.txt"));
    assert!(result.is_err());
}

#[test]
fn test_file_repository_directory_creation() {
    let repo = StandardFileRepository::new();
    let temp_dir = TempDir::new().unwrap();
    let nested_file = temp_dir.path().join("nested").join("deep").join("file.txt");
    let test_content = b"Directory creation test";
    
    // Parent directories should be created automatically
    repo.write_file(&nested_file, test_content).unwrap();
    assert!(repo.file_exists(&nested_file));
    
    let content = repo.read_file(&nested_file).unwrap();
    assert_eq!(content, test_content);
}

#[test]
fn test_empty_file_operations() {
    let repo = StandardFileRepository::new();
    let temp_dir = TempDir::new().unwrap();
    let empty_file = temp_dir.path().join("empty.txt");
    
    // Test empty file
    repo.write_file(&empty_file, b"").unwrap();
    assert!(repo.file_exists(&empty_file));
    
    let metadata = repo.file_metadata(&empty_file).unwrap();
    assert_eq!(metadata.file_size, 0);
    
    // Test secure deletion of empty file
    repo.delete_file_secure(&empty_file).unwrap();
    assert!(!repo.file_exists(&empty_file));
}