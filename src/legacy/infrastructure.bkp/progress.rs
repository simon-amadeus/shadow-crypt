//! # Enhanced Progress Infrastructure
//! 
//! Professional progress reporting for Shadow file operations

use std::time::{Duration, Instant};
use std::io::{self, Write};

/// Visual styles for progress reporting
#[derive(Debug, Clone, PartialEq)]
pub enum ProgressStyle {
    /// Minimal text-only progress
    Minimal,
    /// Animated spinner with context
    Spinner,
    /// Progress bar for determinate operations
    ProgressBar,
    /// Silent mode (no output)
    Silent,
}

/// Rich context for progress operations
#[derive(Debug, Clone)]
pub struct ProgressContext {
    /// Primary operation being performed
    pub operation: String,
    /// Current file being processed (if applicable)
    pub current_file: Option<String>,
    /// Current file index in batch (0-based)
    pub file_index: Option<usize>,
    /// Total files in batch
    pub total_files: Option<usize>,
    /// Current phase of operation
    pub phase: Option<String>,
    /// Elapsed time since operation start
    pub elapsed: Duration,
    /// Bytes processed so far
    pub size_processed: Option<u64>,
    /// Total size to process
    pub total_size: Option<u64>,
}

/// Enhanced progress reporter with visual indicators and timing
pub struct ProgressReporter {
    style: ProgressStyle,
    start_time: Instant,
    last_update: Instant,
    update_threshold: Duration,
}

impl ProgressReporter {
    /// Create new progress reporter with specified style
    pub fn new(style: ProgressStyle) -> Self {
        let now = Instant::now();
        Self {
            style,
            start_time: now,
            last_update: now,
            update_threshold: Duration::from_millis(100), // Throttle updates to 10fps
        }
    }

    /// Create reporter based on quiet mode setting
    pub fn from_quiet_mode(quiet: bool) -> Self {
        if quiet {
            Self::new(ProgressStyle::Silent)
        } else {
            Self::new(ProgressStyle::Spinner)
        }
    }

    /// Report progress with rich context
    pub fn report_with_context(&mut self, context: ProgressContext) {
        // Throttle updates to prevent terminal spam
        let now = Instant::now();
        if now.duration_since(self.last_update) < self.update_threshold {
            return;
        }
        self.last_update = now;

        match &self.style {
            ProgressStyle::Silent => return,
            ProgressStyle::Minimal => self.format_minimal(&context),
            ProgressStyle::Spinner => self.format_spinner(&context),
            ProgressStyle::ProgressBar => self.format_progress_bar(&context),
        }
    }

    /// Simple text progress for backward compatibility
    pub fn report_simple(&self, message: &str) {
        if !matches!(self.style, ProgressStyle::Silent) {
            eprintln!("ℹ️  {}", message);
        }
    }

    /// Report operation completion
    pub fn complete_operation(&self, message: &str) {
        match &self.style {
            ProgressStyle::Silent => return,
            ProgressStyle::Spinner | ProgressStyle::ProgressBar => {
                // Clear current line and print completion
                eprint!("\r\x1b[K");
                eprintln!("✅ {}", message);
            }
            ProgressStyle::Minimal => {
                eprintln!("✅ {}", message);
            }
        }
    }

    /// Report operation error
    pub fn report_error(&self, message: &str) {
        match &self.style {
            ProgressStyle::Silent => return,
            ProgressStyle::Spinner | ProgressStyle::ProgressBar => {
                // Clear current line and print error
                eprint!("\r\x1b[K");
                eprintln!("❌ {}", message);
            }
            ProgressStyle::Minimal => {
                eprintln!("❌ {}", message);
            }
        }
    }

    /// Report warning message
    pub fn report_warning(&self, message: &str) {
        if !matches!(self.style, ProgressStyle::Silent) {
            eprintln!("⚠️  {}", message);
        }
    }

    fn format_minimal(&self, context: &ProgressContext) {
        let elapsed_str = Self::format_duration(context.elapsed);
        
        if let (Some(current), Some(total)) = (context.file_index, context.total_files) {
            eprintln!("[{}/{}] {} ({})", 
                current + 1, total, context.operation, elapsed_str);
        } else {
            eprintln!("[{}] {}", elapsed_str, context.operation);
        }
    }

    fn format_spinner(&self, context: &ProgressContext) {
        let spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        let spinner_idx = (context.elapsed.as_millis() / 100) % spinner_chars.len() as u128;
        let spinner = spinner_chars[spinner_idx as usize];
        
        let elapsed_str = Self::format_duration(context.elapsed);
        
        // Build progress line components
        let file_progress = if let (Some(current), Some(total)) = (context.file_index, context.total_files) {
            format!("[{}/{}] ", current + 1, total)
        } else {
            String::new()
        };
        
        let file_info = if let Some(file) = &context.current_file {
            let filename = std::path::Path::new(file)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(file);
            format!(" • {}", filename)
        } else {
            String::new()
        };
        
        let phase_info = if let Some(phase) = &context.phase {
            format!(" • {}", phase)
        } else {
            String::new()
        };

        let size_info = if let (Some(processed), Some(total)) = (context.size_processed, context.total_size) {
            format!(" • {}/{}", Self::format_bytes(processed), Self::format_bytes(total))
        } else if let Some(processed) = context.size_processed {
            format!(" • {}", Self::format_bytes(processed))
        } else {
            String::new()
        };
        
        // Clear line and write progress
        eprint!("\r\x1b[K{} {}{} ({}){}{}{}", 
            spinner, file_progress, context.operation, elapsed_str, 
            phase_info, file_info, size_info);
        
        let _ = io::stderr().flush();
    }

    fn format_progress_bar(&self, context: &ProgressContext) {
        if let (Some(current), Some(total)) = (context.file_index, context.total_files) {
            let percentage = ((current + 1) as f64 / total as f64 * 100.0) as usize;
            let bar_width = 25;
            let filled = (percentage * bar_width) / 100;
            let empty = bar_width - filled;
            
            let bar = format!("{}{}",
                "█".repeat(filled),
                "░".repeat(empty)
            );
            
            let elapsed_str = Self::format_duration(context.elapsed);
            let eta = if current > 0 {
                let avg_time = context.elapsed.as_secs_f64() / (current + 1) as f64;
                let remaining_files = total - (current + 1);
                let eta_secs = avg_time * remaining_files as f64;
                format!(" ETA {}", Self::format_duration(Duration::from_secs_f64(eta_secs)))
            } else {
                String::new()
            };
            
            let file_info = if let Some(file) = &context.current_file {
                let filename = std::path::Path::new(file)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(file);
                format!(" • {}", filename)
            } else {
                String::new()
            };
            
            eprint!("\r\x1b[K[{}] {}% ({}/{}) {} ({}{}){}", 
                bar, percentage, current + 1, total, 
                context.operation, elapsed_str, eta, file_info);
            
            let _ = io::stderr().flush();
        } else {
            // Fall back to spinner for indeterminate progress
            self.format_spinner(context);
        }
    }

    fn format_duration(duration: Duration) -> String {
        let secs = duration.as_secs_f64();
        if secs < 1.0 {
            format!("{:.0}ms", duration.as_millis())
        } else if secs < 60.0 {
            format!("{:.1}s", secs)
        } else {
            let mins = secs / 60.0;
            format!("{:.1}m", mins)
        }
    }

    fn format_bytes(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
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
}

/// Helper to create progress context for common scenarios
impl ProgressContext {
    pub fn new(operation: String) -> Self {
        Self {
            operation,
            current_file: None,
            file_index: None,
            total_files: None,
            phase: None,
            elapsed: Duration::from_secs(0),
            size_processed: None,
            total_size: None,
        }
    }

    pub fn with_file(mut self, filename: String) -> Self {
        self.current_file = Some(filename);
        self
    }

    pub fn with_batch_info(mut self, current: usize, total: usize) -> Self {
        self.file_index = Some(current);
        self.total_files = Some(total);
        self
    }

    pub fn with_phase(mut self, phase: String) -> Self {
        self.phase = Some(phase);
        self
    }

    pub fn with_elapsed(mut self, elapsed: Duration) -> Self {
        self.elapsed = elapsed;
        self
    }

    pub fn with_size(mut self, processed: u64, total: Option<u64>) -> Self {
        self.size_processed = Some(processed);
        self.total_size = total;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_context_builder() {
        let context = ProgressContext::new("Test operation".to_string())
            .with_file("test.txt".to_string())
            .with_batch_info(2, 5)
            .with_phase("Processing".to_string())
            .with_elapsed(Duration::from_secs(3))
            .with_size(1024, Some(2048));
        
        assert_eq!(context.operation, "Test operation");
        assert_eq!(context.current_file, Some("test.txt".to_string()));
        assert_eq!(context.file_index, Some(2));
        assert_eq!(context.total_files, Some(5));
        assert_eq!(context.phase, Some("Processing".to_string()));
        assert_eq!(context.elapsed, Duration::from_secs(3));
        assert_eq!(context.size_processed, Some(1024));
        assert_eq!(context.total_size, Some(2048));
    }

    #[test]
    fn test_progress_reporter_creation() {
        let reporter = ProgressReporter::new(ProgressStyle::Spinner);
        assert_eq!(reporter.style, ProgressStyle::Spinner);
        
        let quiet_reporter = ProgressReporter::from_quiet_mode(true);
        assert_eq!(quiet_reporter.style, ProgressStyle::Silent);
        
        let verbose_reporter = ProgressReporter::from_quiet_mode(false);
        assert_eq!(verbose_reporter.style, ProgressStyle::Spinner);
    }

    #[test]
    fn test_duration_formatting() {
        assert_eq!(ProgressReporter::format_duration(Duration::from_millis(500)), "500ms");
        assert_eq!(ProgressReporter::format_duration(Duration::from_secs(2)), "2.0s");
        assert_eq!(ProgressReporter::format_duration(Duration::from_secs(65)), "1.1m");
    }

    #[test]
    fn test_byte_formatting() {
        assert_eq!(ProgressReporter::format_bytes(512), "512 B");
        assert_eq!(ProgressReporter::format_bytes(1536), "1.5 KB");
        assert_eq!(ProgressReporter::format_bytes(2048 * 1024), "2.0 MB");
        assert_eq!(ProgressReporter::format_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    #[test]
    fn test_silent_mode() {
        let mut reporter = ProgressReporter::new(ProgressStyle::Silent);
        
        let context = ProgressContext::new("Silent test".to_string());
        
        // These should not panic and should not produce output
        reporter.report_with_context(context);
        reporter.report_simple("Test message");
        reporter.complete_operation("Test completed");
        reporter.report_error("Test error");
        reporter.report_warning("Test warning");
    }

    #[test]
    fn test_throttling() {
        let mut reporter = ProgressReporter::new(ProgressStyle::Minimal);
        reporter.update_threshold = Duration::from_millis(50);
        
        let context = ProgressContext::new("Throttle test".to_string());
        
        // First call should work
        reporter.report_with_context(context.clone());
        
        // Immediate second call should be throttled (no panic)
        reporter.report_with_context(context);
    }
}