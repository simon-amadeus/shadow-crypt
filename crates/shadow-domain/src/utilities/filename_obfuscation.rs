//! # Filename Obfuscation Utility
//!
//! Provides secure filename obfuscation and restoration capabilities
//! for enhanced privacy during file encryption.
//!
//! # Usage Example
//!
//! ```rust
//! use shadow_crypt::domain::utilities::filename_obfuscation::FilenameObfuscator;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Obfuscate a filename for encryption
//! let original_path = Path::new("/home/user/secret_document.pdf");
//! let (obfuscated_path, info) = FilenameObfuscator::create_obfuscated_output_path(
//!     original_path, 
//!     false // Don't preserve extension
//! )?;
//!
//! // The obfuscated path will be something like:
//! // "/home/user/12345678-1234-5678-9abc-123456789abc.shadow"
//! 
//! // Restore original filename during decryption
//! let restored_path = FilenameObfuscator::restore_original_filename(
//!     &obfuscated_path,
//!     "secret_document.pdf"
//! )?;
//! // Result: "/home/user/secret_document.pdf"
//! # Ok(())
//! # }
//! ```

use std::fmt;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use crate::errors::{DomainError, DomainResult};

/// Filename obfuscation service for privacy-enhanced encryption
pub struct FilenameObfuscator;

/// Represents an obfuscated filename with its components
#[derive(Debug, Clone, PartialEq)]
pub struct ObfuscatedFilename {
    /// The obfuscated filename to use for the encrypted file
    pub obfuscated_name: String,
    /// The original filename (stored in TLV header)
    pub original_name: String,
    /// Optional file extension (preserved for compatibility)
    pub extension: Option<String>,
}

impl FilenameObfuscator {
    /// Generate an obfuscated filename while preserving the original filename for recovery
    ///
    /// Uses UUID v4 for cryptographically secure random filenames that don't leak
    /// information about the original file content or name.
    ///
    /// # Security Considerations
    /// - Uses UUID v4 which provides 122 bits of entropy
    /// - No correlation between original filename and obfuscated name
    /// - Safe across all major filesystems (Windows, macOS, Linux)
    /// - Resistant to collision attacks due to UUID design
    ///
    /// # Arguments
    /// * `original_path` - The original file path
    /// * `preserve_extension` - Whether to preserve the file extension for compatibility
    ///
    /// # Returns
    /// An `ObfuscatedFilename` containing the obfuscated name and original metadata
    pub fn obfuscate_filename(
        original_path: &Path, 
        preserve_extension: bool
    ) -> DomainResult<ObfuscatedFilename> {
        let original_filename = original_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| DomainError::InputValidationError(
                crate::errors::InputValidationError::InvalidPath {
                    path: original_path.display().to_string(),
                    reason: "Cannot extract filename from path".to_string(),
                }
            ))?;

        // Generate a cryptographically secure random UUID
        let uuid = Uuid::new_v4();
        let uuid_string = uuid.to_string();

        let (obfuscated_name, extension) = if preserve_extension {
            let extension = original_path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.to_string());
            
            let obfuscated_with_ext = match &extension {
                Some(ext) => format!("{}.{}.shadow", uuid_string, ext),
                None => format!("{}.shadow", uuid_string),
            };
            
            (obfuscated_with_ext, extension)
        } else {
            (format!("{}.shadow", uuid_string), None)
        };

        Ok(ObfuscatedFilename {
            obfuscated_name,
            original_name: original_filename.to_string(),
            extension,
        })
    }

    /// Create an obfuscated output path based on the original input path
    ///
    /// # Arguments
    /// * `input_path` - The original file path
    /// * `preserve_extension` - Whether to preserve the file extension
    ///
    /// # Returns
    /// A tuple of (obfuscated_output_path, obfuscated_filename_info)
    pub fn create_obfuscated_output_path(
        input_path: &Path,
        preserve_extension: bool,
    ) -> DomainResult<(PathBuf, ObfuscatedFilename)> {
        let obfuscated_filename = Self::obfuscate_filename(input_path, preserve_extension)?;
        
        let output_path = if let Some(parent) = input_path.parent() {
            parent.join(&obfuscated_filename.obfuscated_name)
        } else {
            PathBuf::from(&obfuscated_filename.obfuscated_name)
        };

        Ok((output_path, obfuscated_filename))
    }

    /// Restore the original filename from obfuscated filename metadata
    ///
    /// # Arguments
    /// * `obfuscated_path` - The path of the obfuscated encrypted file
    /// * `original_filename` - The original filename retrieved from TLV header
    ///
    /// # Returns
    /// The restored output path with the original filename
    pub fn restore_original_filename(
        obfuscated_path: &Path,
        original_filename: &str,
    ) -> DomainResult<PathBuf> {
        // Validate the original filename doesn't contain path separators for security
        if original_filename.contains('/') || original_filename.contains('\\') {
            return Err(DomainError::SecurityViolation(
                crate::errors::SecurityViolation::SensitiveInformationExposure {
                    context: "Filename contains path separators".to_string(),
                }
            ));
        }

        let restored_path = if let Some(parent) = obfuscated_path.parent() {
            parent.join(original_filename)
        } else {
            PathBuf::from(original_filename)
        };

        Ok(restored_path)
    }

    /// Validate that a filename is safe for cross-platform use
    ///
    /// Checks for reserved names, length limits, and problematic characters
    pub fn validate_filename_safety(filename: &str) -> DomainResult<()> {
        // Check length (most filesystems support at least 255 characters)
        if filename.len() > 255 {
            return Err(DomainError::InputValidationError(
                crate::errors::InputValidationError::InvalidArgument {
                    argument: "filename".to_string(),
                    reason: "Filename exceeds maximum length of 255 characters".to_string(),
                }
            ));
        }

        // Check for empty filename
        if filename.is_empty() {
            return Err(DomainError::InputValidationError(
                crate::errors::InputValidationError::InvalidArgument {
                    argument: "filename".to_string(),
                    reason: "Filename cannot be empty".to_string(),
                }
            ));
        }

        // Check for Windows reserved names (case-insensitive)
        let reserved_names = [
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];
        
        let name_upper = filename.to_uppercase();
        for reserved in &reserved_names {
            if name_upper == *reserved || name_upper.starts_with(&format!("{}.", reserved)) {
                return Err(DomainError::InputValidationError(
                    crate::errors::InputValidationError::InvalidArgument {
                        argument: "filename".to_string(),
                        reason: format!("Filename '{}' conflicts with Windows reserved name", filename),
                    }
                ));
            }
        }

        // Check for problematic characters (broader than strictly necessary for safety)
        let problematic_chars = ['<', '>', ':', '"', '|', '?', '*', '\0'];
        for ch in problematic_chars {
            if filename.contains(ch) {
                return Err(DomainError::InputValidationError(
                    crate::errors::InputValidationError::InvalidArgument {
                        argument: "filename".to_string(),
                        reason: format!("Filename contains problematic character: '{}'", ch),
                    }
                ));
            }
        }

        Ok(())
    }
}

impl fmt::Display for ObfuscatedFilename {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (original: {})", self.obfuscated_name, self.original_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_basic_filename_obfuscation() {
        let input_path = Path::new("/home/user/document.txt");
        let result = FilenameObfuscator::obfuscate_filename(input_path, false).unwrap();
        
        assert_eq!(result.original_name, "document.txt");
        assert_ne!(result.obfuscated_name, "document.txt");
        assert!(result.obfuscated_name.len() > 0);
        assert!(result.obfuscated_name.ends_with(".shadow"));
        assert_eq!(result.extension, None);
    }

    #[test]
    fn test_filename_obfuscation_with_extension() {
        let input_path = Path::new("/home/user/document.txt");
        let result = FilenameObfuscator::obfuscate_filename(input_path, true).unwrap();
        
        assert_eq!(result.original_name, "document.txt");
        assert!(result.obfuscated_name.ends_with(".txt.shadow"));
        assert_eq!(result.extension, Some("txt".to_string()));
    }

    #[test]
    fn test_filename_obfuscation_no_extension() {
        let input_path = Path::new("/home/user/document");
        let result = FilenameObfuscator::obfuscate_filename(input_path, true).unwrap();
        
        assert_eq!(result.original_name, "document");
        assert!(result.obfuscated_name.ends_with(".shadow"));
        assert!(!result.obfuscated_name.contains(".."));
        assert_eq!(result.extension, None);
    }

    #[test]
    fn test_create_obfuscated_output_path() {
        let input_path = Path::new("/home/user/document.txt");
        let (output_path, obfuscated) = FilenameObfuscator::create_obfuscated_output_path(input_path, true).unwrap();
        
        assert_eq!(output_path.parent(), Some(Path::new("/home/user")));
        assert!(output_path.file_name().unwrap().to_str().unwrap().ends_with(".txt.shadow"));
        assert_eq!(obfuscated.original_name, "document.txt");
    }

    #[test]
    fn test_restore_original_filename() {
        let obfuscated_path = Path::new("/home/user/12345678-1234-5678-9abc-123456789abc.shadow");
        let original_filename = "document.txt";
        
        let restored_path = FilenameObfuscator::restore_original_filename(obfuscated_path, original_filename).unwrap();
        
        assert_eq!(restored_path, Path::new("/home/user/document.txt"));
    }

    #[test]
    fn test_restore_filename_security_validation() {
        let obfuscated_path = Path::new("/home/user/12345678-1234-5678-9abc-123456789abc.shadow");
        
        // Test path separator rejection
        let result = FilenameObfuscator::restore_original_filename(obfuscated_path, "../malicious.txt");
        assert!(result.is_err());
        
        let result = FilenameObfuscator::restore_original_filename(obfuscated_path, "sub\\malicious.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_filename_safety_validation() {
        // Valid filenames
        assert!(FilenameObfuscator::validate_filename_safety("document.txt").is_ok());
        assert!(FilenameObfuscator::validate_filename_safety("my-file_123.pdf").is_ok());
        
        // Invalid filenames
        assert!(FilenameObfuscator::validate_filename_safety("").is_err());
        assert!(FilenameObfuscator::validate_filename_safety("CON").is_err());
        assert!(FilenameObfuscator::validate_filename_safety("CON.txt").is_err());
        assert!(FilenameObfuscator::validate_filename_safety("file<name.txt").is_err());
        assert!(FilenameObfuscator::validate_filename_safety("file:name.txt").is_err());
        
        // Long filename
        let long_name = "a".repeat(256);
        assert!(FilenameObfuscator::validate_filename_safety(&long_name).is_err());
    }

    #[test]
    fn test_uuid_uniqueness() {
        let input_path = Path::new("/test/file.txt");
        let result1 = FilenameObfuscator::obfuscate_filename(input_path, false).unwrap();
        let result2 = FilenameObfuscator::obfuscate_filename(input_path, false).unwrap();
        
        // UUIDs should be unique
        assert_ne!(result1.obfuscated_name, result2.obfuscated_name);
        assert_eq!(result1.original_name, result2.original_name);
    }

    #[test]
    fn test_obfuscated_filename_display() {
        let obfuscated = ObfuscatedFilename {
            obfuscated_name: "12345678-1234-5678-9abc-123456789abc.shadow".to_string(),
            original_name: "document.txt".to_string(),
            extension: Some("txt".to_string()),
        };
        
        let display_string = format!("{}", obfuscated);
        assert!(display_string.contains("12345678-1234-5678-9abc-123456789abc.shadow"));
        assert!(display_string.contains("document.txt"));
    }
}