//! Performance benchmark utility
//! 
//! This binary provides performance analysis and benchmarking for Shadow crypto operations.
//! Helps users understand where time is spent and whether timing is appropriate for security.

use shadow_crypt::shared::algorithms::{AesGcmConfig, DefaultConfigProvider, encrypt_with_provider, CryptoConfig};
use shadow_crypt::shared::algorithms::aes_gcm::{derive_master_key, generate_salt};
use shadow_crypt::shared::performance::{PerformanceBenchmark, format_duration};
use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔬 Shadow Performance Analysis");
    println!("=============================\n");
    
    // System information
    show_system_info();
    
    // Run benchmarks
    run_crypto_benchmarks()?;
    run_file_operation_benchmarks()?;
    
    // Show recommendations
    show_recommendations();
    
    Ok(())
}

fn show_system_info() {
    println!("📊 System Information:");
    
    // Get CPU count
    let cpu_count = num_cpus::get();
    println!("   CPUs: {}", cpu_count);
    
    // Get memory info
    let mut sys = sysinfo::System::new_all();
    sys.refresh_memory();
    let total_memory_mb = sys.total_memory() / 1024 / 1024;
    println!("   Memory: {} MB", total_memory_mb);
    
    // Show configuration parameters
    let prod_config = AesGcmConfig::production_config();
    let test_config = AesGcmConfig::test_config();
    
    println!("   Production Argon2: {}KB memory, {} iterations, {} threads", 
             prod_config.argon2_params().memory_cost, 
             prod_config.argon2_params().time_cost, 
             prod_config.argon2_params().parallelism);
    println!("   Test Argon2: {}KB memory, {} iterations, {} threads\n", 
             test_config.argon2_params().memory_cost, 
             test_config.argon2_params().time_cost, 
             test_config.argon2_params().parallelism);
}

fn run_crypto_benchmarks() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Cryptographic Operations Benchmark:");
    
    let mut benchmark = PerformanceBenchmark::new();
    
    // Key derivation benchmarks
    benchmark.add_operation("Key Derivation (Production)", || {
        let password = "benchmark_password_123";
        let salt = generate_salt(16)?;
        let config = AesGcmConfig::production_config();
        let _key_material = derive_master_key(password, &salt, config.argon2_params())?;
        Ok(())
    });
    
    benchmark.add_operation("Key Derivation (Test/Fast)", || {
        let password = "benchmark_password_123";
        let salt = generate_salt(16)?;
        let config = AesGcmConfig::test_config();
        let _key_material = derive_master_key(password, &salt, config.argon2_params())?;
        Ok(())
    });
    
    // Salt generation
    benchmark.add_operation("Salt Generation", || {
        let _salt = generate_salt(16)?;
        Ok(())
    });
    
    let report = benchmark.run_benchmarks();
    println!("{}\n", report.format_report());
    
    // Analysis
    analyze_key_derivation_performance(&report);
    
    Ok(())
}

fn run_file_operation_benchmarks() -> Result<(), Box<dyn std::error::Error>> {
    println!("📁 File Operations Benchmark:");
    
    let temp_dir = TempDir::new()?;
    let mut benchmark = PerformanceBenchmark::new();
    
    // Create test files of different sizes
    let small_file = create_test_file(&temp_dir, "small.txt", 1024)?; // 1KB
    let medium_file = create_test_file(&temp_dir, "medium.txt", 1024 * 1024)?; // 1MB
    let large_file = create_test_file(&temp_dir, "large.txt", 10 * 1024 * 1024)?; // 10MB
    
    let test_password = "benchmark_password";
    
    // Small file operations
    benchmark.add_operation("Encrypt Small File (1KB)", {
        let input = small_file.clone();
        let temp_dir = temp_dir.path().to_path_buf();
        move || {
            let provider = DefaultConfigProvider::<AesGcmConfig>::test(); // Create inside closure
            let output = temp_dir.join("small.txt.shadow");
            encrypt_with_provider(&input, &output, test_password, false, &provider)?;
            Ok(())
        }
    });
    
    // Medium file operations
    benchmark.add_operation("Encrypt Medium File (1MB)", {
        let input = medium_file.clone();
        let temp_dir = temp_dir.path().to_path_buf();
        move || {
            let provider = DefaultConfigProvider::<AesGcmConfig>::test(); // Create inside closure
            let output = temp_dir.join("medium.txt.shadow");
            encrypt_with_provider(&input, &output, test_password, false, &provider)?;
            Ok(())
        }
    });
    
    // Large file operations  
    benchmark.add_operation("Encrypt Large File (10MB)", {
        let input = large_file.clone();
        let temp_dir = temp_dir.path().to_path_buf();
        move || {
            let provider = DefaultConfigProvider::<AesGcmConfig>::test(); // Create inside closure
            let output = temp_dir.join("large.txt.shadow");
            encrypt_with_provider(&input, &output, test_password, false, &provider)?;
            Ok(())
        }
    });
    
    let report = benchmark.run_benchmarks();
    println!("{}\n", report.format_report());
    
    // Analysis
    analyze_file_operation_performance(&report);
    
    Ok(())
}

fn create_test_file(temp_dir: &TempDir, name: &str, size: usize) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let file_path = temp_dir.path().join(name);
    let mut file = File::create(&file_path)?;
    
    // Write test data
    let test_data = vec![b'X'; size];
    file.write_all(&test_data)?;
    
    Ok(file_path)
}

fn analyze_key_derivation_performance(report: &shadow_crypt::shared::performance::BenchmarkReport) {
    println!("🔍 Key Derivation Analysis:");
    
    let prod_time = report.results.iter()
        .find(|r| r.name.contains("Production"))
        .map(|r| r.duration);
        
    let test_time = report.results.iter()
        .find(|r| r.name.contains("Test/Fast"))
        .map(|r| r.duration);
    
    if let (Some(prod), Some(test)) = (prod_time, test_time) {
        let ratio = prod.as_millis() as f64 / test.as_millis() as f64;
        println!("   Production is {:.1}x slower than test parameters", ratio);
        
        if prod.as_millis() > 2000 {
            println!("   ⚠️  Production key derivation is slow ({})", format_duration(prod));
            println!("      This is NORMAL and IMPORTANT for security!");
            println!("      Slow key derivation protects against brute force attacks.");
        } else if prod.as_millis() > 500 {
            println!("   ✅ Production key derivation is appropriately secure ({})", format_duration(prod));
        } else {
            println!("   ⚠️  Production key derivation may be too fast ({})", format_duration(prod));
            println!("      Consider increasing Argon2 parameters for better security.");
        }
    }
    
    println!();
}

fn analyze_file_operation_performance(report: &shadow_crypt::shared::performance::BenchmarkReport) {
    println!("🔍 File Operation Analysis:");
    
    // Calculate throughput for different file sizes
    let file_sizes = [
        ("Small File (1KB)", 1024),
        ("Medium File (1MB)", 1024 * 1024),
        ("Large File (10MB)", 10 * 1024 * 1024),
    ];
    
    for (name, size) in &file_sizes {
        if let Some(result) = report.results.iter().find(|r| r.name.contains(name)) {
            if result.success {
                let mb_per_sec = (*size as f64) / (1024.0 * 1024.0) / result.duration.as_secs_f64();
                println!("   {}: {:.1} MB/s", name, mb_per_sec);
            }
        }
    }
    
    println!();
}

fn show_recommendations() {
    println!("💡 Performance Recommendations:");
    println!("   1. For testing/development: Use test Argon2 parameters for faster operations");
    println!("   2. For production: Current parameters provide good security/performance balance");
    println!("   3. For very large files: Consider using streaming mode (future enhancement)");
    println!("   4. For batch operations: Use multi-file commands for parallel processing");
    println!("   5. On slow systems: Key derivation time is expected - this protects your data!");
}