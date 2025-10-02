//! Beautiful UI formatting for the shadows tool
//! 
//! This module provides color-coded, visually appealing formatting for displaying
//! encrypted file information with clear sections and visual hierarchy.

use colored::*;
use crate::listing::file_scanner::FileInfo;
use std::time::{SystemTime, UNIX_EPOCH};

/// Color scheme for the UI
pub struct ColorScheme {
    pub success: Color,
    pub warning: Color, 
    pub error: Color,
    pub info: Color,
    pub header: Color,
    pub filename: Color,
    pub size: Color,
    pub timestamp: Color,
}

impl Default for ColorScheme {
    fn default() -> Self {
        Self {
            success: Color::Green,
            warning: Color::Yellow,
            error: Color::Red,
            info: Color::Cyan,
            header: Color::Blue,
            filename: Color::White,
            size: Color::Magenta,
            timestamp: Color::BrightBlack,
        }
    }
}

/// Enhanced formatter for file information display
pub struct UIFormatter {
    color_scheme: ColorScheme,
    use_colors: bool,
}

impl UIFormatter {
    /// Create a new UI formatter
    pub fn new() -> Self {
        Self {
            color_scheme: ColorScheme::default(),
            use_colors: Self::should_use_colors(),
        }
    }
    
    /// Create a formatter without colors (for compatibility)
    pub fn without_colors() -> Self {
        Self {
            color_scheme: ColorScheme::default(),
            use_colors: false,
        }
    }
    
    /// Check if colors should be used based on terminal capabilities
    fn should_use_colors() -> bool {
        // Check if we're in a terminal that supports colors
        colored::control::SHOULD_COLORIZE.should_colorize()
    }
    
    /// Format the main header with title and description
    pub fn format_title(&self, total_files: usize) -> String {
        let title = if self.use_colors {
            "📂 Shadow File Listing".bold().color(self.color_scheme.header)
        } else {
            "Shadow File Listing".normal()
        };
        
        let description = if self.use_colors {
            format!("Found {} encrypted file(s)", total_files)
                .color(self.color_scheme.info)
        } else {
            format!("Found {} encrypted file(s)", total_files).normal()
        };
        
        format!("{}\n{}\n", title, description)
    }
    
    /// Format the column headers
    pub fn format_headers(&self) -> String {
        let status_header = if self.use_colors {
            "STATUS".bold().color(self.color_scheme.header)
        } else {
            "STATUS".normal()
        };
        
        let original_header = if self.use_colors {
            "ORIGINAL NAME".bold().color(self.color_scheme.header)
        } else {
            "ORIGINAL NAME".normal()
        };
        
        let obfuscated_header = if self.use_colors {
            "OBFUSCATED NAME".bold().color(self.color_scheme.header)
        } else {
            "OBFUSCATED NAME".normal()
        };
        
        let size_header = if self.use_colors {
            "ORIGINAL SIZE".bold().color(self.color_scheme.header)
        } else {
            "ORIGINAL SIZE".normal()
        };
        
        let encrypted_size_header = if self.use_colors {
            "ENCRYPTED SIZE".bold().color(self.color_scheme.header)
        } else {
            "ENCRYPTED SIZE".normal()
        };
        
        let modified_header = if self.use_colors {
            "MODIFIED".bold().color(self.color_scheme.header)
        } else {
            "MODIFIED".normal()
        };
        
        format!(
            "{:<8} {:<30} {:<25} {:>12} {:>14} {:>20}",
            status_header, original_header, obfuscated_header, size_header, encrypted_size_header, modified_header
        )
    }
    
    /// Format a separator line
    pub fn format_separator(&self) -> String {
        let separator = "─".repeat(112); // Updated width to accommodate new column structure
        if self.use_colors {
            separator.color(self.color_scheme.header).dimmed().to_string()
        } else {
            separator
        }
    }
    
    /// Truncate text to fit within specified width, adding ellipsis if needed
    fn truncate_with_ellipsis(&self, text: &str, max_width: usize) -> String {
        if text.chars().count() <= max_width {
            text.to_string()
        } else {
            let truncated: String = text.chars().take(max_width.saturating_sub(3)).collect();
            format!("{}...", truncated)
        }
    }
    
    /// Format individual file information
    pub fn format_file_info(&self, info: &FileInfo) -> String {
        // Calculate the plain text for each column to determine proper spacing
        let status_plain = if info.filename_decrypted { "✓" } else { "✗" };
        
        let original_name_plain = if info.filename_decrypted {
            self.truncate_with_ellipsis(&info.original_name, 30)
        } else {
            "[ENCRYPTED]".to_string()
        };
        
        let obfuscated_name_plain = self.truncate_with_ellipsis(&info.obfuscated_name, 25);
        let size_plain = self.format_file_size(info.size);
        let encrypted_size_plain = self.format_file_size(info.encrypted_size);
        let timestamp_plain = self.format_timestamp(info.modified);
        
        // Apply colors if enabled
        let status_colored = if self.use_colors {
            let color = if info.filename_decrypted {
                self.color_scheme.success
            } else {
                self.color_scheme.error
            };
            status_plain.color(color).bold().to_string()
        } else {
            status_plain.to_string()
        };
        
        let original_name_colored = if self.use_colors {
            if info.filename_decrypted {
                original_name_plain.color(self.color_scheme.filename).bold().to_string()
            } else {
                original_name_plain.color(self.color_scheme.error).dimmed().to_string()
            }
        } else {
            original_name_plain.clone()
        };
        
        let obfuscated_name_colored = if self.use_colors {
            obfuscated_name_plain.color(self.color_scheme.warning).dimmed().to_string()
        } else {
            obfuscated_name_plain.clone()
        };
        
        let size_colored = if self.use_colors {
            size_plain.color(self.color_scheme.size).to_string()
        } else {
            size_plain.clone()
        };
        
        let encrypted_size_colored = if self.use_colors {
            encrypted_size_plain.color(self.color_scheme.size).dimmed().to_string()
        } else {
            encrypted_size_plain.clone()
        };
        
        let timestamp_colored = if self.use_colors {
            timestamp_plain.color(self.color_scheme.timestamp).to_string()
        } else {
            timestamp_plain.clone()
        };
        
        // Manually construct the line with proper spacing
        let mut line = String::new();
        
        // Status column (9 chars)
        line.push_str(&status_colored);
        line.push_str(&" ".repeat(9 - status_plain.chars().count()));
        
        // Original name column (31 chars)
        line.push_str(&original_name_colored);
        line.push_str(&" ".repeat(31 - original_name_plain.chars().count()));
        
        // Obfuscated name column (26 chars)
        line.push_str(&obfuscated_name_colored);
        line.push_str(&" ".repeat(26 - obfuscated_name_plain.chars().count()));
        
        // Size column (13 chars, right-aligned)
        let size_padding = 13 - size_plain.chars().count();
        line.push_str(&" ".repeat(size_padding));
        line.push_str(&size_colored);
        
        // Encrypted size column (15 chars, right-aligned)
        let encrypted_size_padding = 15 - encrypted_size_plain.chars().count();
        line.push_str(&" ".repeat(encrypted_size_padding));
        line.push_str(&encrypted_size_colored);
        
        // Timestamp column (21 chars, right-aligned)
        let timestamp_padding = 21 - timestamp_plain.chars().count();
        line.push_str(&" ".repeat(timestamp_padding));
        line.push_str(&timestamp_colored);
        
        line
    }
    
    /// Format the legend/help section
    pub fn format_legend(&self) -> String {
        let legend_title = if self.use_colors {
            "\n📋 Legend:".bold().color(self.color_scheme.header)
        } else {
            "\nLegend:".normal()
        };
        
        let success_line = if self.use_colors {
            format!("  {} = Original filename successfully decrypted", 
                   "✓".color(self.color_scheme.success).bold())
        } else {
            "  ✓ = Original filename successfully decrypted".to_string()
        };
        
        let error_line = if self.use_colors {
            format!("  {} = Filename encrypted (wrong password or corrupted)", 
                   "✗".color(self.color_scheme.error).bold())
        } else {
            "  ✗ = Filename encrypted (wrong password or corrupted)".to_string()
        };
        
        let note = if self.use_colors {
            "     [ENCRYPTED] appears in original name column when decryption fails"
                .color(self.color_scheme.info).dimmed()
        } else {
            "     [ENCRYPTED] appears in original name column when decryption fails".normal()
        };
        
        format!("{}\n{}\n{}\n{}\n", legend_title, success_line, error_line, note)
    }
    
    /// Format file size in human-readable format
    fn format_file_size(&self, size: u64) -> String {
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
    fn format_timestamp(&self, time: SystemTime) -> String {
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
}

impl Default for UIFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_color_scheme_creation() {
        let scheme = ColorScheme::default();
        assert_eq!(scheme.success, Color::Green);
        assert_eq!(scheme.error, Color::Red);
    }
    
    #[test]
    fn test_formatter_creation() {
        let formatter = UIFormatter::new();
        assert_eq!(formatter.color_scheme.success, Color::Green);
        
        let formatter_no_color = UIFormatter::without_colors();
        assert_eq!(formatter_no_color.use_colors, false);
    }
    
    #[test]
    fn test_file_size_formatting() {
        let formatter = UIFormatter::without_colors();
        assert_eq!(formatter.format_file_size(0), "0 B");
        assert_eq!(formatter.format_file_size(512), "512 B");
        assert_eq!(formatter.format_file_size(1024), "1.0 KB");
        assert_eq!(formatter.format_file_size(1536), "1.5 KB");
        assert_eq!(formatter.format_file_size(1048576), "1.0 MB");
    }
    
    #[test]
    fn test_separator_formatting() {
        let formatter = UIFormatter::without_colors();
        let separator = formatter.format_separator();
        // Check character count, not byte count (Unicode ─ characters)
        assert_eq!(separator.chars().count(), 112);
        assert!(separator.chars().all(|c| c == '─'));
    }
    
    #[test]
    fn test_title_formatting() {
        let formatter = UIFormatter::without_colors();
        let title = formatter.format_title(5);
        assert!(title.contains("Shadow File Listing"));
        assert!(title.contains("Found 5 encrypted file(s)"));
    }
}