//! Performance analysis and timing instrumentation
//! 
//! This module provides tools for measuring and analyzing performance characteristics
//! of cryptographic operations, helping users understand where time is spent and
//! whether the timing is appropriate for security requirements.

use std::time::{Duration, Instant};
use std::collections::HashMap;

/// Performance timer for measuring operation phases
pub struct PerformanceTimer {
    start_time: Instant,
    phase_times: HashMap<String, Duration>,
    current_phase: Option<(String, Instant)>,
}

impl PerformanceTimer {
    /// Create a new performance timer
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            phase_times: HashMap::new(),
            current_phase: None,
        }
    }
    
    /// Start timing a new phase
    pub fn start_phase(&mut self, phase_name: &str) {
        // End current phase if one is running
        if let Some((current_name, start_time)) = self.current_phase.take() {
            let duration = start_time.elapsed();
            self.phase_times.insert(current_name, duration);
        }
        
        // Start new phase
        self.current_phase = Some((phase_name.to_string(), Instant::now()));
    }
    
    /// End the current phase
    pub fn end_phase(&mut self) {
        if let Some((phase_name, start_time)) = self.current_phase.take() {
            let duration = start_time.elapsed();
            self.phase_times.insert(phase_name, duration);
        }
    }
    
    /// Get total elapsed time
    pub fn total_elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
    
    /// Get timing for a specific phase
    pub fn phase_time(&self, phase_name: &str) -> Option<Duration> {
        self.phase_times.get(phase_name).copied()
    }
    
    /// Get all phase timings
    pub fn all_phase_times(&self) -> &HashMap<String, Duration> {
        &self.phase_times
    }
    
    /// Generate a performance report
    pub fn generate_report(&self) -> PerformanceReport {
        let total_time = self.total_elapsed();
        let phases: Vec<PhaseStats> = self.phase_times
            .iter()
            .map(|(name, duration)| PhaseStats {
                name: name.clone(),
                duration: *duration,
                percentage: if total_time.as_nanos() > 0 {
                    (duration.as_nanos() as f64 / total_time.as_nanos() as f64) * 100.0
                } else {
                    0.0
                },
            })
            .collect();
        
        PerformanceReport {
            total_time,
            phases,
        }
    }
}

/// Performance statistics for a single phase
#[derive(Debug, Clone)]
pub struct PhaseStats {
    pub name: String,
    pub duration: Duration,
    pub percentage: f64,
}

/// Complete performance report
#[derive(Debug)]
pub struct PerformanceReport {
    pub total_time: Duration,
    pub phases: Vec<PhaseStats>,
}

impl PerformanceReport {
    /// Format as a human-readable performance breakdown
    pub fn format_detailed(&self) -> String {
        let mut report = String::new();
        
        report.push_str(&format!("📊 Performance Analysis\n"));
        report.push_str(&format!("Total time: {}\n", format_duration(self.total_time)));
        report.push_str(&format!("\nPhase breakdown:\n"));
        
        // Sort phases by duration (longest first)
        let mut sorted_phases = self.phases.clone();
        sorted_phases.sort_by(|a, b| b.duration.cmp(&a.duration));
        
        for phase in &sorted_phases {
            report.push_str(&format!(
                "  {:<20} {:>8} ({:>5.1}%)\n",
                phase.name,
                format_duration(phase.duration),
                phase.percentage
            ));
        }
        
        // Add security context for key derivation
        if let Some(kdf_phase) = sorted_phases.iter().find(|p| p.name.contains("key_derivation") || p.name.contains("Key Derivation")) {
            if kdf_phase.percentage > 50.0 {
                report.push_str(&format!("\n💡 Most time spent on key derivation - this is normal for security!\n"));
                report.push_str(&format!("   Strong password hashing protects against brute force attacks.\n"));
            }
        }
        
        report
    }
    
    /// Format as a compact one-line summary
    pub fn format_summary(&self) -> String {
        format!(
            "⏱️  Total: {} ({} phases)",
            format_duration(self.total_time),
            self.phases.len()
        )
    }
}

/// Format duration in a human-readable way with appropriate precision
pub fn format_duration(duration: Duration) -> String {
    let total_millis = duration.as_millis();
    
    if total_millis >= 60_000 {
        // Minutes and seconds for very long operations
        let minutes = total_millis / 60_000;
        let seconds = (total_millis % 60_000) / 1000;
        format!("{}m {}.{}s", minutes, seconds, (total_millis % 1000) / 100)
    } else if total_millis >= 1000 {
        // Seconds with decimal precision
        let seconds = total_millis / 1000;
        let decimal = (total_millis % 1000) / 100;
        format!("{}.{}s", seconds, decimal)
    } else if total_millis > 0 {
        // Milliseconds for fast operations
        format!("{}ms", total_millis)
    } else {
        // Microseconds for very fast operations
        let micros = duration.as_micros();
        if micros > 0 {
            format!("{}μs", micros)
        } else {
            "< 1μs".to_string()
        }
    }
}

/// Benchmark utility for measuring typical operation performance
pub struct PerformanceBenchmark {
    operations: Vec<(&'static str, Box<dyn Fn() -> Result<(), Box<dyn std::error::Error>>>)>,
}

impl PerformanceBenchmark {
    /// Create a new benchmark suite
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
        }
    }
    
    /// Add an operation to benchmark
    pub fn add_operation<F>(&mut self, name: &'static str, operation: F)
    where
        F: Fn() -> Result<(), Box<dyn std::error::Error>> + 'static,
    {
        self.operations.push((name, Box::new(operation)));
    }
    
    /// Run all benchmarks and generate report
    pub fn run_benchmarks(&self) -> BenchmarkReport {
        let mut results = Vec::new();
        
        for (name, operation) in &self.operations {
            let start = Instant::now();
            let result = operation();
            let duration = start.elapsed();
            
            results.push(BenchmarkResult {
                name: name.to_string(),
                duration,
                success: result.is_ok(),
                error: if let Err(e) = result {
                    Some(e.to_string())
                } else {
                    None
                },
            });
        }
        
        BenchmarkReport { results }
    }
}

/// Result of a single benchmark operation
#[derive(Debug)]
pub struct BenchmarkResult {
    pub name: String,
    pub duration: Duration,
    pub success: bool,
    pub error: Option<String>,
}

/// Complete benchmark report
#[derive(Debug)]
pub struct BenchmarkReport {
    pub results: Vec<BenchmarkResult>,
}

impl BenchmarkReport {
    /// Format benchmark results
    pub fn format_report(&self) -> String {
        let mut report = String::new();
        
        report.push_str("🔬 Performance Benchmark Results\n");
        report.push_str("=================================\n\n");
        
        for result in &self.results {
            let status = if result.success { "✅" } else { "❌" };
            report.push_str(&format!(
                "{} {:<25} {}\n",
                status,
                result.name,
                format_duration(result.duration)
            ));
            
            if let Some(error) = &result.error {
                report.push_str(&format!("   Error: {}\n", error));
            }
        }
        
        // Calculate statistics
        let successful_results: Vec<_> = self.results.iter().filter(|r| r.success).collect();
        if !successful_results.is_empty() {
            let total_time: Duration = successful_results.iter().map(|r| r.duration).sum();
            let avg_time = total_time / successful_results.len() as u32;
            
            report.push_str(&format!("\n📊 Summary:\n"));
            report.push_str(&format!("   Successful operations: {}/{}\n", successful_results.len(), self.results.len()));
            report.push_str(&format!("   Average time: {}\n", format_duration(avg_time)));
            report.push_str(&format!("   Total time: {}\n", format_duration(total_time)));
        }
        
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration as StdDuration;
    
    #[test]
    fn test_performance_timer() {
        let mut timer = PerformanceTimer::new();
        
        timer.start_phase("Phase 1");
        thread::sleep(StdDuration::from_millis(10));
        
        timer.start_phase("Phase 2");
        thread::sleep(StdDuration::from_millis(5));
        timer.end_phase();
        
        let report = timer.generate_report();
        assert_eq!(report.phases.len(), 2);
        assert!(report.total_time >= StdDuration::from_millis(15));
    }
    
    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_millis(500)), "500ms");
        assert_eq!(format_duration(Duration::from_millis(1500)), "1.5s");
        assert_eq!(format_duration(Duration::from_millis(65000)), "1m 5.0s");
    }
    
    #[test]
    fn test_benchmark() {
        let mut benchmark = PerformanceBenchmark::new();
        
        benchmark.add_operation("fast_operation", || {
            thread::sleep(StdDuration::from_millis(1));
            Ok(())
        });
        
        benchmark.add_operation("failing_operation", || {
            Err("Test error".into())
        });
        
        let report = benchmark.run_benchmarks();
        assert_eq!(report.results.len(), 2);
        assert!(report.results[0].success);
        assert!(!report.results[1].success);
    }
}