// shadow-shell/src/cli_helpers.rs
// CLI parsing and user interaction utilities

use rpassword;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::errors::{ShellError, ShellResult};
use shadow_core::{SecureString, validate_password_strength};

/// Parse glob patterns and expand to file paths
/// Side effect: File system traversal
pub fn parse_glob_patterns(patterns: &[String]) -> ShellResult<Vec<PathBuf>> {
    if patterns.is_empty() {
        return Err(ShellError::NoFilesMatched);
    }

    let mut all_paths = Vec::new();

    for pattern in patterns {
        // Simple implementation - in production you'd use the glob crate
        let path = PathBuf::from(pattern);

        if path.exists() {
            if path.is_file() {
                all_paths.push(path);
            } else if path.is_dir() {
                // For directories, we could recursively find files
                // For now, treat as an error
                return Err(ShellError::NotAFile(path));
            }
        } else {
            // Pattern didn't match anything
            return Err(ShellError::FileNotFound(path));
        }
    }

    if all_paths.is_empty() {
        return Err(ShellError::NoFilesMatched);
    }

    // Remove duplicates
    all_paths.sort();
    all_paths.dedup();

    Ok(all_paths)
}

/// Prompt user for password with confirmation
/// Side effect: User interaction via stdin/stdout
pub fn prompt_for_password(allow_weak: bool) -> ShellResult<SecureString> {
    print!("Enter password: ");
    io::stdout()
        .flush()
        .map_err(|e| ShellError::UserInput(format!("Failed to flush stdout: {}", e)))?;

    let password1 = rpassword::read_password()
        .map_err(|e| ShellError::UserInput(format!("Failed to read password: {}", e)))?;

    print!("Confirm password: ");
    io::stdout()
        .flush()
        .map_err(|e| ShellError::UserInput(format!("Failed to flush stdout: {}", e)))?;

    let password2 = rpassword::read_password()
        .map_err(|e| ShellError::UserInput(format!("Failed to read password: {}", e)))?;

    if password1 != password2 {
        return Err(ShellError::PasswordMismatch);
    }

    if password1.is_empty() {
        return Err(ShellError::UserInput(
            "Empty password not allowed".to_string(),
        ));
    }

    // Convert to SecureString for validation
    let secure_password = SecureString::new(password1.clone());

    // Validate password strength only if not allowing weak passwords
    if !allow_weak {
        validate_password_strength(&secure_password).map_err(|e| ShellError::Validation(e))?;
    }

    Ok(SecureString::new(password1))
}

/// Confirm overwrite operation with user
/// Side effect: User interaction via stdin/stdout
pub fn confirm_overwrite(path: &std::path::Path) -> ShellResult<bool> {
    print!(
        "File '{}' already exists. Overwrite? [y/N]: ",
        path.display()
    );
    io::stdout()
        .flush()
        .map_err(|e| ShellError::UserInput(format!("Failed to flush stdout: {}", e)))?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| ShellError::UserInput(format!("Failed to read input: {}", e)))?;

    let input = input.trim().to_lowercase();
    Ok(input == "y" || input == "yes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_parse_glob_patterns_single_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, b"content").unwrap();

        let patterns = vec![test_file.to_string_lossy().to_string()];
        let result = parse_glob_patterns(&patterns).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], test_file);
    }

    #[test]
    fn test_parse_glob_patterns_empty() {
        let result = parse_glob_patterns(&[]);
        assert!(matches!(result, Err(ShellError::NoFilesMatched)));
    }

    #[test]
    fn test_parse_glob_patterns_not_found() {
        let patterns = vec!["nonexistent.txt".to_string()];
        let result = parse_glob_patterns(&patterns);
        assert!(matches!(result, Err(ShellError::FileNotFound(_))));
    }
}
