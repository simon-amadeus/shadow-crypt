//! Metadata extraction and formatting for Phase 8
//! 
//! This module provides functions to extract file information and format it
//! for display in the cryptls tool.

use crate::shared::errors::CryptoError;
use crate::listing::file_scanner::FileInfo;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Extract file information from an encrypted file
/// 
/// This function provides detailed file information by leveraging the file scanner
/// to extract metadata and format it appropriately.
pub fn extract_file_info(path: &Path, password: &str) -> Result<FileInfo, CryptoError> {
    // Use file scanner to get the information for a single file
    let parent_dir = path.parent().ok_or_else(|| {
        CryptoError::InvalidFileFormat
    })?;
    
    let files = crate::listing::file_scanner::list_encrypted_files(parent_dir, password)?;
    
    // Find the specific file in the results
    files.into_iter()
        .find(|info| info.encrypted_path == path)
        .ok_or_else(|| CryptoError::InvalidFileFormat)
}

/// Format file size in human-readable format
pub fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    
    if size == 0 {
        return "0 B".to_string();
    }
    
    let mut size_f = size as f64;
    let mut unit_index = 0;
    
    while size_f >= 1024.0 && unit_index < UNITS.len() - 1 {
        size_f /= 1024.0;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{} {}", size, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size_f, UNITS[unit_index])
    }
}

/// Format timestamp in human-readable format
pub fn format_timestamp(time: SystemTime) -> String {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            // Simple timestamp formatting without external dependencies
            let days = secs / 86400;
            let hours = (secs % 86400) / 3600;
            let minutes = (secs % 3600) / 60;
            let seconds = secs % 60;
            
            // Basic date formatting (Unix epoch + days approximation)
            let epoch_days = 19_000; // Approximate days since Unix epoch to 2022
            let total_days = epoch_days + days;
            let years = total_days / 365;
            let remaining_days = total_days % 365;
            let months = remaining_days / 30;
            let day_of_month = remaining_days % 30;
            
            format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", 
                    1970 + years, 1 + months, 1 + day_of_month, hours, minutes, seconds)
        },
        Err(_) => "Unknown".to_string(),
    }
}

/// Format file information for display
pub fn format_file_info(info: &FileInfo) -> String {
    format!(
        "{:<40} {:>10} {:>15} {}",
        info.original_name,
        format_file_size(info.size),
        format_file_size(info.encrypted_size),
        format_timestamp(info.modified)
    )
}

/// Format file listing header
pub fn format_header() -> String {
    format!(
        "{:<40} {:>10} {:>15} {}",
        "ORIGINAL NAME", "SIZE", "ENCRYPTED SIZE", "MODIFIED"
    )
}

/// Format separator line
pub fn format_separator() -> String {
    "-".repeat(80)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_file_size() {
        assert_eq!(format_file_size(0), "0 B");
        assert_eq!(format_file_size(512), "512 B");
        assert_eq!(format_file_size(1024), "1.0 KB");
        assert_eq!(format_file_size(1536), "1.5 KB");
        assert_eq!(format_file_size(1048576), "1.0 MB");
        assert_eq!(format_file_size(1073741824), "1.0 GB");
    }

    #[test]
    fn test_format_header() {
        let header = format_header();
        assert!(header.contains("ORIGINAL NAME"));
        assert!(header.contains("SIZE"));
        assert!(header.contains("ENCRYPTED SIZE"));
        assert!(header.contains("MODIFIED"));
    }

    #[test]
    fn test_format_separator() {
        let sep = format_separator();
        assert_eq!(sep.len(), 80);
        assert!(sep.chars().all(|c| c == '-'));
    }
}