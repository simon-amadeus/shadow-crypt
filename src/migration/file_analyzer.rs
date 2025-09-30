//! File analysis functionality for migration system
//! 
//! Analyzes Shadow encrypted files to determine version compatibility and migration needs.

use crate::shared::{CryptoError, VersionInfo, Header};
use std::path::{Path, PathBuf};
use std::fs;

/// Analysis result for a Shadow encrypted file
#[derive(Debug, Clone)]
pub struct FileAnalysis {
    pub file_path: PathBuf,
    pub version_info: VersionInfo,
    pub file_size: u64,
    pub is_shadow_file: bool,
    pub header_valid: bool,
}

/// Analyze a single Shadow file for migration needs
pub fn analyze_shadow_file(file_path: &Path) -> Result<Option<FileAnalysis>, CryptoError> {
    // Check if file exists and is readable
    if !file_path.exists() {
        return Err(CryptoError::FileSystemError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("File not found: {}", file_path.display())
        )));
    }
    
    // Check if it's a .shadow file
    if file_path.extension().and_then(|s| s.to_str()) != Some("shadow") {
        return Ok(None);
    }
    
    // Get file size
    let metadata = fs::metadata(file_path)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    let file_size = metadata.len();
    
    // Try to read and parse header
    let file_data = fs::read(file_path)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    match Header::deserialize(&file_data) {
        Ok((header, _)) => {
            let version_info = header.get_version_info();
            let header_valid = header.is_valid().is_ok();
            
            Ok(Some(FileAnalysis {
                file_path: file_path.to_path_buf(),
                version_info,
                file_size,
                is_shadow_file: true,
                header_valid,
            }))
        }
        Err(_) => {
            // File has .shadow extension but invalid header
            Ok(None)
        }
    }
}

/// Analyze all Shadow files in a directory
pub fn analyze_directory(dir_path: &Path) -> Result<Vec<FileAnalysis>, CryptoError> {
    let mut analyses = Vec::new();
    
    if !dir_path.is_dir() {
        return Err(CryptoError::FileSystemError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a directory", dir_path.display())
        )));
    }
    
    // Scan for .shadow files
    let entries = fs::read_dir(dir_path)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    for entry in entries {
        let entry = entry.map_err(|e| CryptoError::FileSystemError(e))?;
        let path = entry.path();
        
        // Only analyze .shadow files
        if path.extension().and_then(|s| s.to_str()) == Some("shadow") {
            match analyze_shadow_file(&path) {
                Ok(Some(analysis)) => analyses.push(analysis),
                Ok(None) => continue, // Not a valid Shadow file
                Err(e) => {
                    // Log error but continue with other files
                    eprintln!("Warning: Could not analyze {}: {}", path.display(), e);
                }
            }
        }
    }
    
    Ok(analyses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_analyze_nonexistent_file() {
        let result = analyze_shadow_file(Path::new("/nonexistent/file.shadow"));
        assert!(result.is_err());
    }
    
    #[test]
    fn test_analyze_non_shadow_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "not a shadow file").unwrap();
        
        let result = analyze_shadow_file(&file_path).unwrap();
        assert!(result.is_none());
    }
    
    #[test]
    fn test_analyze_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let result = analyze_directory(temp_dir.path()).unwrap();
        assert!(result.is_empty());
    }
    
    #[test]
    fn test_analyze_nonexistent_directory() {
        let result = analyze_directory(Path::new("/nonexistent/directory"));
        assert!(result.is_err());
    }
}