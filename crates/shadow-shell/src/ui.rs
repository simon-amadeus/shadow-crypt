// shadow-shell/src/ui.rs
// User interface utilities with side effects (terminal output)

use std::io::{self, Write};
use colored::Colorize;

use crate::errors::ShellError;

/// Display progress for file operations
/// Side effect: Terminal output
pub fn display_progress(current: u64, total: u64, file: &str) {
    if total == 0 {
        return;
    }
    
    // Only show progress for larger files (> 10MB) to avoid spam
    if total > 10 * 1024 * 1024 {
        let percent = (current as f64 / total as f64) * 100.0;
        let bar_width = 40;
        let filled = ((percent / 100.0) * bar_width as f64) as usize;
        let empty = bar_width - filled;
        
        let bar = format!("[{}{}]", 
            "=".repeat(filled).green(),
            " ".repeat(empty)
        );
        
        print!("\r{} {} {:.1}% ({})", 
            "Processing".blue().bold(),
            bar,
            percent,
            file.yellow()
        );
        io::stdout().flush().ok();
        
        if current >= total {
            println!(); // New line when complete
        }
    }
}

/// Display success message
/// Side effect: Terminal output
pub fn display_success(message: &str) {
    println!("{} {}", "✓".green().bold(), message);
}

/// Display warning message  
/// Side effect: Terminal output
pub fn display_warning(message: &str) {
    eprintln!("{} {}", "⚠".yellow().bold(), message.yellow());
}

/// Display info message
/// Side effect: Terminal output
pub fn display_info(message: &str) {
    println!("{} {}", "ℹ".blue().bold(), message);
}

/// Display error message with appropriate formatting
/// Side effect: Terminal output
pub fn display_error(error: &ShellError) {
    eprintln!("{} {}", "✗".red().bold(), error.to_string().red());
    
    // Add helpful hints for common errors
    display_error_hint(error);
}

/// Display helpful hints for specific errors
/// Side effect: Terminal output
fn display_error_hint(error: &ShellError) {
    let hint = match error {
        ShellError::OutputExists(_) => {
            Some("Use --force to overwrite existing files".dimmed())
        }
        ShellError::PermissionDenied(_) => {
            Some("Check file permissions or run with appropriate privileges".dimmed())
        }
        ShellError::PasswordMismatch => {
            Some("Passwords must match exactly. Try again.".dimmed())
        }
        ShellError::DuplicateContent { .. } => {
            Some("Use --force to encrypt anyway, or delete existing encrypted file".dimmed())
        }
        ShellError::FileTooLarge { limit, .. } => {
            Some(format!("Maximum file size is {} bytes", limit).dimmed())
        }
        ShellError::TooManyFiles { limit, .. } => {
            Some(format!("Maximum {} files can be processed at once", limit).dimmed())
        }
        ShellError::InsufficientDiskSpace => {
            Some("Free up disk space or choose a different output location".dimmed())
        }
        _ => None,
    };
    
    if let Some(hint) = hint {
        eprintln!("  {}", hint);
    }
}

/// Display operation summary
/// Side effect: Terminal output
pub fn display_summary(
    operation: &str,
    files_processed: usize,
    bytes_processed: u64,
    duration_ms: u64,
) {
    println!();
    println!("{}", "Summary".bold().underline());
    println!("Operation: {}", operation.cyan());
    println!("Files processed: {}", files_processed.to_string().green());
    println!("Bytes processed: {}", format_bytes(bytes_processed).green());
    
    if duration_ms > 0 {
        let throughput = (bytes_processed as f64 / duration_ms as f64) * 1000.0;
        println!("Duration: {} ms", duration_ms.to_string().blue());
        println!("Throughput: {}/s", format_bytes(throughput as u64).blue());
    }
}

/// Display file operation result
/// Side effect: Terminal output
pub fn display_file_result(
    input_file: &str,
    output_file: &str,
    operation: &str,
    success: bool,
) {
    if success {
        println!("{} {} {} -> {}", 
            "✓".green().bold(),
            operation.cyan(),
            input_file.yellow(),
            output_file.green()
        );
    } else {
        println!("{} {} {} -> {}", 
            "✗".red().bold(),
            operation.cyan(),
            input_file.yellow(),
            output_file.red()
        );
    }
}

/// Display list of files to be processed
/// Side effect: Terminal output
pub fn display_file_list(files: &[std::path::PathBuf], operation: &str) {
    if files.is_empty() {
        return;
    }
    
    println!("{} {} {} file{}:",
        "ℹ".blue().bold(),
        "Will".blue(),
        operation.cyan(),
        if files.len() == 1 { "" } else { "s" }
    );
    
    for (i, file) in files.iter().enumerate() {
        let prefix = if i == files.len() - 1 { "└─" } else { "├─" };
        println!("  {} {}", prefix.dimmed(), file.display().to_string().yellow());
    }
    println!();
}

/// Display confirmation prompt
/// Side effect: Terminal output and input
pub fn prompt_confirmation(message: &str) -> io::Result<bool> {
    print!("{} {} [y/N]: ", "?".yellow().bold(), message);
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    let input = input.trim().to_lowercase();
    Ok(input == "y" || input == "yes")
}

/// Display a banner or header
/// Side effect: Terminal output
pub fn display_banner(title: &str, version: &str) {
    println!("{}", title.bright_cyan().bold());
    println!("{} {}", "Version".dimmed(), version.dimmed());
    println!();
}

/// Format bytes in human-readable format
/// Pure function - no side effects
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

/// Check if we should use colored output
/// Side effect: Environment variable check
pub fn should_use_color() -> bool {
    // Check NO_COLOR environment variable
    if std::env::var("NO_COLOR").is_ok() {
        return false;
    }
    
    // Check if stdout is a terminal
    atty::is(atty::Stream::Stdout)
}

/// Initialize colored output based on environment
/// Side effect: Global color configuration
pub fn init_colors() {
    if !should_use_color() {
        colored::control::set_override(false);
    }
}

/// Display a table of information
/// Side effect: Terminal output
pub fn display_table(headers: &[&str], rows: &[Vec<&str>]) {
    if headers.is_empty() || rows.is_empty() {
        return;
    }
    
    // Calculate column widths
    let mut widths = headers.iter().map(|h| h.len()).collect::<Vec<_>>();
    
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }
    
    // Print header
    print!("│");
    for (i, header) in headers.iter().enumerate() {
        print!(" {:width$} │", header.bold(), width = widths[i]);
    }
    println!();
    
    // Print separator
    print!("├");
    for width in &widths {
        print!("{}", "─".repeat(width + 2));
        print!("┼");
    }
    // Remove last character and replace with ┤
    print!("\x08┤"); 
    println!();
    
    // Print rows
    for row in rows {
        print!("│");
        for (i, cell) in row.iter().enumerate() {
            let width = widths.get(i).unwrap_or(&0);
            print!(" {:width$} │", cell, width = width);
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(format_bytes(1024_u64.pow(4)), "1.0 TB");
    }

    #[test]
    fn test_format_bytes_large() {
        let large_size = 2_500_000_000_u64; // 2.5 GB
        let result = format_bytes(large_size);
        assert!(result.contains("2.3 GB") || result.contains("2.4 GB")); // Account for floating point precision
    }

    #[test]
    fn test_display_functions_dont_panic() {
        // These tests just ensure the functions don't panic
        display_success("Test success");
        display_warning("Test warning");
        display_info("Test info");
        display_banner("Test App", "1.0.0");
        
        let files = vec![
            std::path::PathBuf::from("test1.txt"),
            std::path::PathBuf::from("test2.txt"),
        ];
        display_file_list(&files, "encrypt");
        
        display_file_result("input.txt", "output.txt.shadow", "encrypted", true);
        display_file_result("input.txt", "output.txt.shadow", "encrypted", false);
        
        display_summary("encryption", 5, 1024 * 1024, 1000);
    }

    #[test]
    fn test_display_table() {
        let headers = vec!["Name", "Size", "Status"];
        let rows = vec![
            vec!["file1.txt", "1.5 KB", "encrypted"],
            vec!["file2.txt", "2.0 MB", "failed"],
        ];
        
        // Just test that it doesn't panic
        display_table(&headers, &rows);
    }

    #[test]
    fn test_display_table_empty() {
        display_table(&[], &[]);
        display_table(&["Header"], &[]);
    }

    #[test]
    fn test_shell_error_hints() {
        use std::path::PathBuf;
        
        // Test that error display doesn't panic
        let errors = vec![
            ShellError::OutputExists(PathBuf::from("test.txt")),
            ShellError::PermissionDenied(PathBuf::from("test.txt")),
            ShellError::PasswordMismatch,
            ShellError::DuplicateContent {
                original_file: PathBuf::from("test.txt"),
                content_hash: "abc123".to_string(),
            },
            ShellError::FileTooLarge { size: 1000, limit: 500 },
            ShellError::TooManyFiles { count: 1001, limit: 1000 },
            ShellError::InsufficientDiskSpace,
            ShellError::Cancelled,
        ];
        
        for error in errors {
            display_error(&error);
        }
    }
}