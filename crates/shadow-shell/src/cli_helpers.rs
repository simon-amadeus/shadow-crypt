// shadow-shell/src/cli_helpers.rs
// CLI parsing and user interaction utilities

use std::path::PathBuf;
use std::io::{self, Write};
use rpassword;

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
pub fn prompt_for_password() -> ShellResult<SecureString> {
    print!("Enter password: ");
    io::stdout().flush()
        .map_err(|e| ShellError::UserInput(format!("Failed to flush stdout: {}", e)))?;
    
    let password1 = rpassword::read_password()
        .map_err(|e| ShellError::UserInput(format!("Failed to read password: {}", e)))?;
    
    print!("Confirm password: ");
    io::stdout().flush()
        .map_err(|e| ShellError::UserInput(format!("Failed to flush stdout: {}", e)))?;
    
    let password2 = rpassword::read_password()
        .map_err(|e| ShellError::UserInput(format!("Failed to read password: {}", e)))?;
    
    if password1 != password2 {
        return Err(ShellError::PasswordMismatch);
    }
    
    if password1.is_empty() {
        return Err(ShellError::UserInput("Empty password not allowed".to_string()));
    }
    
    // Validate password strength
    validate_password_strength(&password1)
        .map_err(|e| ShellError::Validation(e))?;
    
    Ok(SecureString::new(password1))
}

/// Prompt user for password without confirmation (for decryption)
/// Side effect: User interaction via stdin/stdout  
pub fn prompt_for_password_single() -> ShellResult<SecureString> {
    print!("Enter password: ");
    io::stdout().flush()
        .map_err(|e| ShellError::UserInput(format!("Failed to flush stdout: {}", e)))?;
    
    let password = rpassword::read_password()
        .map_err(|e| ShellError::UserInput(format!("Failed to read password: {}", e)))?;
    
    if password.is_empty() {
        return Err(ShellError::UserInput("Empty password not allowed".to_string()));
    }
    
    Ok(SecureString::new(password))
}

/// Confirm overwrite operation with user
/// Side effect: User interaction via stdin/stdout
pub fn confirm_overwrite(path: &std::path::Path) -> ShellResult<bool> {
    print!("File '{}' already exists. Overwrite? [y/N]: ", path.display());
    io::stdout().flush()
        .map_err(|e| ShellError::UserInput(format!("Failed to flush stdout: {}", e)))?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)
        .map_err(|e| ShellError::UserInput(format!("Failed to read input: {}", e)))?;
    
    let input = input.trim().to_lowercase();
    Ok(input == "y" || input == "yes")
}

/// Confirm potentially dangerous operation
/// Side effect: User interaction via stdin/stdout
pub fn confirm_operation(message: &str) -> ShellResult<bool> {
    print!("{} [y/N]: ", message);
    io::stdout().flush()
        .map_err(|e| ShellError::UserInput(format!("Failed to flush stdout: {}", e)))?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)
        .map_err(|e| ShellError::UserInput(format!("Failed to read input: {}", e)))?;
    
    let input = input.trim().to_lowercase();
    Ok(input == "y" || input == "yes")
}

/// Parse file size from string (e.g., "10MB", "1.5GB")
/// Pure function - no side effects
pub fn parse_file_size(size_str: &str) -> ShellResult<u64> {
    let size_str = size_str.trim().to_lowercase();
    
    if size_str.is_empty() {
        return Err(ShellError::UserInput("Empty size string".to_string()));
    }
    
    // Extract number and unit
    let (number_part, unit_part) = if size_str.ends_with("kb") {
        (&size_str[..size_str.len()-2], "kb")
    } else if size_str.ends_with("mb") {
        (&size_str[..size_str.len()-2], "mb")
    } else if size_str.ends_with("gb") {
        (&size_str[..size_str.len()-2], "gb")
    } else if size_str.ends_with("b") {
        (&size_str[..size_str.len()-1], "b")
    } else {
        // No unit, assume bytes
        (size_str.as_str(), "b")
    };
    
    let number: f64 = number_part.parse()
        .map_err(|_| ShellError::UserInput(format!("Invalid number: {}", number_part)))?;
    
    if number < 0.0 {
        return Err(ShellError::UserInput("Size cannot be negative".to_string()));
    }
    
    let multiplier = match unit_part {
        "b" => 1,
        "kb" => 1_024,
        "mb" => 1_024 * 1_024,
        "gb" => 1_024 * 1_024 * 1_024,
        _ => return Err(ShellError::UserInput(format!("Unknown unit: {}", unit_part))),
    };
    
    let result = (number * multiplier as f64) as u64;
    Ok(result)
}

/// Validate CLI argument combinations
/// Pure function - no side effects
pub fn validate_cli_args(
    input_files: &[PathBuf],
    force: bool,
    obfuscate: bool,
    _keep: bool,
) -> ShellResult<()> {
    if input_files.is_empty() {
        return Err(ShellError::UserInput("No input files specified".to_string()));
    }
    
    // Additional validation logic could go here
    // For example, warning about obfuscation with multiple files
    if obfuscate && input_files.len() > 1 {
        // This is fine, just noting it
    }
    
    if force {
        // Force flag is valid in all contexts
    }
    
    Ok(())
}

/// Generate suggested output filename
/// Pure function - no side effects
pub fn generate_output_filename(
    input_path: &std::path::Path,
    obfuscate: bool,
    encrypt: bool,
) -> ShellResult<String> {
    let input_name = input_path.file_name()
        .ok_or_else(|| ShellError::InvalidFilename("No filename".to_string()))?
        .to_string_lossy();
    
    if encrypt {
        if obfuscate {
            // Generate random UUID-based filename
            use uuid::Uuid;
            Ok(format!("{}.shadow", Uuid::new_v4()))
        } else {
            // Append .shadow extension
            Ok(format!("{}.shadow", input_name))
        }
    } else {
        // Decryption - remove .shadow extension
        if input_name.ends_with(".shadow") {
            let base_name = &input_name[..input_name.len() - 7]; // Remove ".shadow"
            if base_name.is_empty() {
                Ok("decrypted_file".to_string())
            } else {
                Ok(base_name.to_string())
            }
        } else {
            // Input doesn't have .shadow extension, add prefix
            Ok(format!("decrypted_{}", input_name))
        }
    }
}

/// Check if running in interactive terminal
/// Side effect: Terminal detection
pub fn is_interactive() -> bool {
    atty::is(atty::Stream::Stdin) && atty::is(atty::Stream::Stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

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

    #[test]
    fn test_parse_file_size_bytes() {
        assert_eq!(parse_file_size("100").unwrap(), 100);
        assert_eq!(parse_file_size("100b").unwrap(), 100);
        assert_eq!(parse_file_size("100B").unwrap(), 100);
    }

    #[test]
    fn test_parse_file_size_kb() {
        assert_eq!(parse_file_size("1kb").unwrap(), 1024);
        assert_eq!(parse_file_size("1KB").unwrap(), 1024);
        assert_eq!(parse_file_size("1.5kb").unwrap(), 1536);
    }

    #[test]
    fn test_parse_file_size_mb() {
        assert_eq!(parse_file_size("1mb").unwrap(), 1024 * 1024);
        assert_eq!(parse_file_size("1MB").unwrap(), 1024 * 1024);
        assert_eq!(parse_file_size("2.5mb").unwrap(), (2.5 * 1024.0 * 1024.0) as u64);
    }

    #[test]
    fn test_parse_file_size_gb() {
        assert_eq!(parse_file_size("1gb").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_file_size("1GB").unwrap(), 1024 * 1024 * 1024);
    }

    #[test]
    fn test_parse_file_size_invalid() {
        assert!(parse_file_size("").is_err());
        assert!(parse_file_size("abc").is_err());
        assert!(parse_file_size("-1mb").is_err());
        assert!(parse_file_size("1xx").is_err());
    }

    #[test]
    fn test_validate_cli_args_no_files() {
        let result = validate_cli_args(&[], false, false, false);
        assert!(matches!(result, Err(ShellError::UserInput(_))));
    }

    #[test]
    fn test_validate_cli_args_valid() {
        let files = vec![PathBuf::from("test.txt")];
        let result = validate_cli_args(&files, false, false, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_output_filename_encrypt_no_obfuscate() {
        let input = PathBuf::from("test.txt");
        let result = generate_output_filename(&input, false, true).unwrap();
        assert_eq!(result, "test.txt.shadow");
    }

    #[test]
    fn test_generate_output_filename_encrypt_obfuscate() {
        let input = PathBuf::from("test.txt");
        let result = generate_output_filename(&input, true, true).unwrap();
        assert!(result.ends_with(".shadow"));
        assert!(result.len() > "test.txt.shadow".len()); // Should be UUID-based
    }

    #[test]
    fn test_generate_output_filename_decrypt() {
        let input = PathBuf::from("test.txt.shadow");
        let result = generate_output_filename(&input, false, false).unwrap();
        assert_eq!(result, "test.txt");
    }

    #[test]
    fn test_generate_output_filename_decrypt_no_extension() {
        let input = PathBuf::from("test.txt");
        let result = generate_output_filename(&input, false, false).unwrap();
        assert_eq!(result, "decrypted_test.txt");
    }

    #[test]
    fn test_generate_output_filename_decrypt_only_extension() {
        let input = PathBuf::from(".shadow");
        let result = generate_output_filename(&input, false, false).unwrap();
        assert_eq!(result, "decrypted_file");
    }

    #[test]
    fn test_generate_output_filename_no_filename() {
        let input = PathBuf::from("/");
        let result = generate_output_filename(&input, false, true);
        assert!(matches!(result, Err(ShellError::InvalidFilename(_))));
    }
}