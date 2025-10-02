//! Beautiful UI formatting for the shadows tool
//! 
//! This module provides color-coded, visually appealing formatting for displaying
//! encrypted file information using a modern grid layout system.

use colored::*;
use crate::listing::file_scanner::FileInfo;
use crate::listing::modern_grid::{TerminalGrid, ColumnConfig, GridRow, Alignment};
use std::time::{SystemTime, UNIX_EPOCH};

/// Enhanced formatter for file information display using modern grid layout
pub struct UIFormatter {
    use_colors: bool,
}

impl UIFormatter {
    /// Create a new UI formatter
    pub fn new() -> Self {
        Self {
            use_colors: Self::should_use_colors(),
        }
    }
    
    /// Create a formatter without colors (for compatibility)
    pub fn without_colors() -> Self {
        Self {
            use_colors: false,
        }
    }
    
    /// Check if colors should be used based on terminal capabilities
    fn should_use_colors() -> bool {
        // Check if we're in a terminal that supports colors
        colored::control::SHOULD_COLORIZE.should_colorize()
    }
    
    /// Format complete file listing with modern grid layout
    pub fn format_file_listing(&self, files: &[FileInfo]) -> String {
        let mut output = String::new();
        
        // Add title
        output.push_str(&self.format_title(files.len()));
        output.push('\n');
        
        if files.is_empty() {
            return output;
        }
        
        // Create grid configuration
        let columns = vec![
            ColumnConfig::new("STATUS", 8, Alignment::Left),
            ColumnConfig::new("ORIGINAL NAME", 40, Alignment::Left),
            ColumnConfig::new("OBFUSCATED NAME", 20, Alignment::Left),
            ColumnConfig::new("SIZE", 12, Alignment::Right),
            ColumnConfig::new("ENCRYPTED", 12, Alignment::Right),
            ColumnConfig::new("MODIFIED", 22, Alignment::Right),
        ];
        
        let mut grid = if self.use_colors {
            TerminalGrid::new(columns)
        } else {
            TerminalGrid::without_colors(columns)
        };
        
        // Add data rows
        for info in files {
            let row = self.create_file_row(info);
            grid.add_row(row);
        }
        
        // Render grid
        output.push_str(&grid.render());
        
        // Add legend
        output.push_str(&self.format_legend());
        
        output
    }
    
    /// Create a grid row for a file info
    fn create_file_row(&self, info: &FileInfo) -> GridRow {
        let status = if info.filename_decrypted { "✓" } else { "✗" };
        let original_name = if info.filename_decrypted {
            info.original_name.clone()
        } else {
            "[ENCRYPTED]".to_string()
        };
        let obfuscated_name = info.obfuscated_name.clone();
        let original_size = self.format_file_size(info.size);
        let encrypted_size = self.format_file_size(info.encrypted_size);
        let modified = self.format_timestamp(info.modified);
        
        let row = GridRow::new(vec![
            status.to_string(),
            original_name,
            obfuscated_name,
            original_size,
            encrypted_size,
            modified,
        ]);
        
        // Apply colors if enabled
        if self.use_colors {
            let status_color = if info.filename_decrypted {
                Color::Green
            } else {
                Color::Red
            };
            
            let name_color = if info.filename_decrypted {
                Color::White
            } else {
                Color::Red
            };
            
            row.with_cell_color(0, status_color)   // Status
                .with_cell_color(1, name_color)     // Original name
                .with_cell_color(2, Color::Yellow)  // Obfuscated name
                .with_cell_color(3, Color::Magenta) // Original size
                .with_cell_color(4, Color::Magenta) // Encrypted size
                .with_cell_color(5, Color::BrightBlack) // Timestamp
        } else {
            row
        }
    }
    
    /// Format the main header with title and description
    pub fn format_title(&self, total_files: usize) -> String {
        let title = if self.use_colors {
            "📂 Shadow File Listing".bold().color(Color::Blue)
        } else {
            "Shadow File Listing".normal()
        };
        
        let description = if self.use_colors {
            format!("Found {} encrypted file(s)", total_files)
                .color(Color::Cyan)
        } else {
            format!("Found {} encrypted file(s)", total_files).normal()
        };
        
        format!("{}\n{}\n", title, description)
    }
    
    /// Format the legend/help section
    pub fn format_legend(&self) -> String {
        let legend_title = if self.use_colors {
            "\n📋 Legend:".bold().color(Color::Blue)
        } else {
            "\nLegend:".normal()
        };
        
        let success_line = if self.use_colors {
            format!("  {} = Original filename successfully decrypted", 
                   "✓".color(Color::Green).bold())
        } else {
            "  ✓ = Original filename successfully decrypted".to_string()
        };
        
        let error_line = if self.use_colors {
            format!("  {} = Filename encrypted (wrong password or corrupted)", 
                   "✗".color(Color::Red).bold())
        } else {
            "  ✗ = Filename encrypted (wrong password or corrupted)".to_string()
        };
        
        let note = if self.use_colors {
            "     [ENCRYPTED] appears in original name column when decryption fails"
                .color(Color::Cyan).dimmed()
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
    fn test_formatter_creation() {
        let formatter = UIFormatter::new();
        // Just check it creates successfully
        assert_eq!(formatter.use_colors, UIFormatter::should_use_colors());
        
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
    fn test_title_formatting() {
        let formatter = UIFormatter::without_colors();
        let title = formatter.format_title(5);
        assert!(title.contains("Shadow File Listing"));
        assert!(title.contains("Found 5 encrypted file(s)"));
    }
    
    #[test]
    fn test_legend_formatting() {
        let formatter = UIFormatter::without_colors();
        let legend = formatter.format_legend();
        assert!(legend.contains("Legend:"));
        assert!(legend.contains("✓ = Original filename successfully decrypted"));
        assert!(legend.contains("✗ = Filename encrypted"));
    }
    
    #[test]
    fn test_complete_file_listing() {
        use std::time::SystemTime;
        use std::path::PathBuf;
        
        let formatter = UIFormatter::without_colors();
        let test_files = vec![
            FileInfo {
                obfuscated_name: "test1.shadow".to_string(),
                original_name: "document.txt".to_string(),
                encrypted_path: PathBuf::from("test1.shadow"),
                size: 1024,
                encrypted_size: 1080,
                modified: SystemTime::UNIX_EPOCH,
                filename_decrypted: true,
            },
            FileInfo {
                obfuscated_name: "test2.shadow".to_string(),
                original_name: "".to_string(),
                encrypted_path: PathBuf::from("test2.shadow"),
                size: 2048,
                encrypted_size: 2104,
                modified: SystemTime::UNIX_EPOCH,
                filename_decrypted: false,
            },
        ];
        
        let output = formatter.format_file_listing(&test_files);
        
        // Check that it contains expected elements
        assert!(output.contains("Shadow File Listing"));
        assert!(output.contains("Found 2 encrypted file(s)"));
        assert!(output.contains("STATUS"));
        assert!(output.contains("ORIGINAL NAME"));
        assert!(output.contains("document.txt"));
        assert!(output.contains("[ENCRYPTED]"));
        assert!(output.contains("test1.shadow"));
        assert!(output.contains("test2.shadow"));
        assert!(output.contains("─")); // Separator
        assert!(output.contains("Legend:"));
    }
}