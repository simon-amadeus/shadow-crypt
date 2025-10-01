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
        
        let filename_header = if self.use_colors {
            "FILENAME MAPPING".bold().color(self.color_scheme.header)
        } else {
            "FILENAME MAPPING".normal()
        };
        
        let size_header = if self.use_colors {
            "SIZE".bold().color(self.color_scheme.header)
        } else {
            "SIZE".normal()
        };
        
        let encrypted_size_header = if self.use_colors {
            "ENCRYPTED".bold().color(self.color_scheme.header)
        } else {
            "ENCRYPTED".normal()
        };
        
        let modified_header = if self.use_colors {
            "MODIFIED".bold().color(self.color_scheme.header)
        } else {
            "MODIFIED".normal()
        };
        
        format!(
            "{:<8} {:<45} {:>10} {:>12} {}",
            status_header, filename_header, size_header, encrypted_size_header, modified_header
        )
    }
    
    /// Format a separator line
    pub fn format_separator(&self) -> String {
        let separator = "─".repeat(90);
        if self.use_colors {
            separator.color(self.color_scheme.header).dimmed().to_string()
        } else {
            separator
        }
    }
    
    /// Format individual file information
    pub fn format_file_info(&self, info: &FileInfo) -> String {
        // Status indicator with color
        let (status_icon, status_color) = if info.filename_decrypted {
            ("✓", self.color_scheme.success)
        } else {
            ("✗", self.color_scheme.error)
        };
        
        let status = if self.use_colors {
            status_icon.color(status_color).bold()
        } else {
            status_icon.normal()
        };
        
        // Filename mapping with appropriate styling
        let filename_display = if info.filename_decrypted {
            let obfuscated = if self.use_colors {
                info.obfuscated_name.color(self.color_scheme.warning).dimmed()
            } else {
                info.obfuscated_name.as_str().normal()
            };
            
            let arrow = if self.use_colors {
                " → ".color(self.color_scheme.info)
            } else {
                " -> ".normal()
            };
            
            let original = if self.use_colors {
                info.original_name.color(self.color_scheme.filename).bold()
            } else {
                info.original_name.as_str().normal()
            };
            
            format!("{}{}{}", obfuscated, arrow, original)
        } else {
            let obfuscated = if self.use_colors {
                info.obfuscated_name.color(self.color_scheme.warning)
            } else {
                info.obfuscated_name.as_str().normal()
            };
            
            let encrypted_label = if self.use_colors {
                " → [ENCRYPTED]".color(self.color_scheme.error).dimmed()
            } else {
                " -> [ENCRYPTED]".normal()
            };
            
            format!("{}{}", obfuscated, encrypted_label)
        };
        
        // File sizes with color
        let size = if self.use_colors {
            self.format_file_size(info.size).color(self.color_scheme.size)
        } else {
            self.format_file_size(info.size).normal()
        };
        
        let encrypted_size = if self.use_colors {
            self.format_file_size(info.encrypted_size).color(self.color_scheme.size).dimmed()
        } else {
            self.format_file_size(info.encrypted_size).normal()
        };
        
        // Timestamp with color
        let timestamp = if self.use_colors {
            self.format_timestamp(info.modified).color(self.color_scheme.timestamp)
        } else {
            self.format_timestamp(info.modified).normal()
        };
        
        format!(
            "{:<8} {:<45} {:>10} {:>12} {}",
            status, filename_display, size, encrypted_size, timestamp
        )
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
            "     [ENCRYPTED] entries show the obfuscated filename only"
                .color(self.color_scheme.info).dimmed()
        } else {
            "     [ENCRYPTED] entries show the obfuscated filename only".normal()
        };
        
        format!("{}\n{}\n{}\n{}", legend_title, success_line, error_line, note)
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
        assert_eq!(separator.chars().count(), 90);
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