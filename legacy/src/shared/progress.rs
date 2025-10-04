//! Progress reporting utilities for multi-file operations
//! 
//! Provides enhanced progress indicators with timing, throughput, and estimates.
//! Also supports single-file operation progress with phase reporting.

use std::time::{Duration, Instant};

/// Progress reporter for single-file operations with phase tracking
pub struct SingleFileProgress {
    start_time: Instant,
    current_phase: Option<(String, Instant)>,
    completed_phases: Vec<(String, Duration)>,
    show_phases: bool,
}

impl SingleFileProgress {
    /// Create a new single-file progress reporter
    pub fn new(show_phases: bool) -> Self {
        Self {
            start_time: Instant::now(),
            current_phase: None,
            completed_phases: Vec::new(),
            show_phases,
        }
    }
    
    /// Start a new phase of the operation
    pub fn start_phase(&mut self, phase_name: &str) {
        // End current phase if one is running
        if let Some((current_name, start_time)) = self.current_phase.take() {
            let duration = start_time.elapsed();
            self.completed_phases.push((current_name, duration));
        }
        
        // Start new phase
        if self.show_phases {
            print!("🔄 {}...", phase_name);
            std::io::Write::flush(&mut std::io::stdout()).ok();
        }
        self.current_phase = Some((phase_name.to_string(), Instant::now()));
    }
    
    /// End the current phase with success
    pub fn end_phase(&mut self) {
        if let Some((phase_name, start_time)) = self.current_phase.take() {
            let duration = start_time.elapsed();
            self.completed_phases.push((phase_name, duration));
            
            if self.show_phases {
                println!(" ✓ ({})", crate::shared::performance::format_duration(duration));
            }
        }
    }
    
    /// End the current phase with error
    pub fn end_phase_with_error(&mut self, error: &str) {
        if let Some((phase_name, start_time)) = self.current_phase.take() {
            let duration = start_time.elapsed();
            self.completed_phases.push((phase_name, duration));
            
            if self.show_phases {
                println!(" ❌ ({}) - {}", crate::shared::performance::format_duration(duration), error);
            }
        }
    }
    
    /// Get total elapsed time
    pub fn total_elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
    
    /// Show a simple spinner for ongoing operations
    pub fn show_spinner(&self, message: &str) {
        if self.show_phases {
            print!("⏳ {}...", message);
            std::io::Write::flush(&mut std::io::stdout()).ok();
        }
    }
    
    /// Complete the spinner with success
    pub fn complete_spinner(&self) {
        if self.show_phases {
            println!(" ✓");
        }
    }
}

/// Progress reporter for multi-file operations
pub struct ProgressReporter {
    start_time: Instant,
    total_files: usize,
    completed_files: usize,
}

impl ProgressReporter {
    /// Create a new progress reporter
    pub fn new(total_files: usize) -> Self {
        Self {
            start_time: Instant::now(),
            total_files,
            completed_files: 0,
        }
    }
    
    /// Report progress for a completed file
    pub fn report_completed(&mut self) {
        self.completed_files += 1;
    }
    
    /// Get current progress statistics
    pub fn get_stats(&self) -> ProgressStats {
        let elapsed = self.start_time.elapsed();
        let files_per_sec = if elapsed.as_secs_f64() > 0.0 {
            self.completed_files as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        
        let estimated_total_time = if self.completed_files > 0 {
            let avg_time_per_file = elapsed.as_secs_f64() / self.completed_files as f64;
            Duration::from_secs_f64(avg_time_per_file * self.total_files as f64)
        } else {
            Duration::from_secs(0)
        };
        
        let estimated_remaining = if estimated_total_time > elapsed {
            estimated_total_time - elapsed
        } else {
            Duration::from_secs(0)
        };
        
        ProgressStats {
            completed: self.completed_files,
            total: self.total_files,
            elapsed,
            files_per_sec,
            estimated_remaining,
        }
    }
    
    /// Format progress as a percentage
    pub fn progress_percentage(&self) -> f64 {
        if self.total_files == 0 {
            0.0
        } else {
            (self.completed_files as f64 / self.total_files as f64) * 100.0
        }
    }
}

/// Progress statistics for multi-file operations
pub struct ProgressStats {
    pub completed: usize,
    pub total: usize,
    pub elapsed: Duration,
    pub files_per_sec: f64,
    pub estimated_remaining: Duration,
}

impl ProgressStats {
    /// Format as a human-readable progress line
    pub fn format_progress_line(&self) -> String {
        format!(
            "[{}/{}] {:.1}% - {:.1} files/sec - ETA: {}",
            self.completed,
            self.total,
            (self.completed as f64 / self.total as f64) * 100.0,
            self.files_per_sec,
            format_duration(self.estimated_remaining)
        )
    }
    
    /// Format final summary
    pub fn format_summary(&self) -> String {
        format!(
            "📊 Completed {} files in {} (avg: {:.1} files/sec)",
            self.completed,
            format_duration(self.elapsed),
            self.files_per_sec
        )
    }
}

/// Format duration in a human-readable way
pub fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    
    if total_secs >= 3600 {
        let hours = total_secs / 3600;
        let minutes = (total_secs % 3600) / 60;
        let seconds = total_secs % 60;
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if total_secs >= 60 {
        let minutes = total_secs / 60;
        let seconds = total_secs % 60;
        format!("{}m {}s", minutes, seconds)
    } else if total_secs > 0 {
        format!("{}s", total_secs)
    } else {
        let millis = duration.as_millis();
        if millis > 0 {
            format!("{}ms", millis)
        } else {
            "< 1ms".to_string()
        }
    }
}

/// Format file size in human-readable units
pub fn format_file_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: f64 = 1024.0;
    
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= THRESHOLD && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

/// Show minimal progress for multi-file operations
/// Displays simple "🔄 Operation X files... ✓ (duration)" format
pub fn show_minimal_multifile_progress<F, R>(
    operation: &str,
    file_count: usize,
    show_progress: bool,
    operation_fn: F,
) -> R
where
    F: FnOnce() -> R,
{
    let start_time = Instant::now();
    
    if show_progress {
        print!("🔄 {} {} file{}...", operation, file_count, if file_count == 1 { "" } else { "s" });
        std::io::Write::flush(&mut std::io::stdout()).ok();
    }
    
    let result = operation_fn();
    
    if show_progress {
        let duration = start_time.elapsed();
        println!(" ✓ ({})", crate::shared::performance::format_duration(duration));
    }
    
    result
}

/// Report minimal multi-file operation completion with success/failure summary
pub fn report_minimal_multifile_completion(
    operation: &str,
    total_files: usize,
    successful_count: usize,
    failed_count: usize,
    total_duration: Duration,
    show_progress: bool,
) {
    if !show_progress {
        return;
    }
    
    if failed_count == 0 {
        // All successful
        println!("✅ {} {} file{} successfully in {}", 
                operation, 
                successful_count,
                if successful_count == 1 { "" } else { "s" },
                crate::shared::performance::format_duration(total_duration));
    } else if successful_count == 0 {
        // All failed
        println!("❌ {} failed for all {} file{} in {}",
                operation,
                total_files,
                if total_files == 1 { "" } else { "s" },
                crate::shared::performance::format_duration(total_duration));
    } else {
        // Mixed results
        println!("⚠️  {} {}/{} file{} completed in {} ({} failed)",
                operation,
                successful_count,
                total_files,
                if total_files == 1 { "" } else { "s" },
                crate::shared::performance::format_duration(total_duration),
                failed_count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_progress_reporter() {
        let mut reporter = ProgressReporter::new(10);
        assert_eq!(reporter.progress_percentage(), 0.0);
        
        reporter.report_completed();
        assert_eq!(reporter.progress_percentage(), 10.0);
        
        reporter.report_completed();
        assert_eq!(reporter.progress_percentage(), 20.0);
        
        let stats = reporter.get_stats();
        assert_eq!(stats.completed, 2);
        assert_eq!(stats.total, 10);
    }
    
    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_millis(500)), "500ms");
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m 1s");
    }
    
    #[test]
    fn test_format_file_size() {
        assert_eq!(format_file_size(512), "512 B");
        assert_eq!(format_file_size(1536), "1.5 KB");
        assert_eq!(format_file_size(2 * 1024 * 1024), "2.0 MB");
        assert_eq!(format_file_size(3 * 1024 * 1024 * 1024), "3.0 GB");
    }
}