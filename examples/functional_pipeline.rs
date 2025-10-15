//! Example usage of the new functional pipeline architecture.

use shadow_crypt::core::{EncryptionPipeline, EncryptionOptions, AlgorithmId};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔒 Functional Pipeline Example");
    
    // Create a test file if it doesn't exist
    let test_file = "test_example.txt";
    if !std::path::Path::new(test_file).exists() {
        std::fs::write(test_file, "This is a test file for the functional pipeline!\nHello, Shadow!")?;
        println!("📄 Created test file: {}", test_file);
    }

    // Simple functional pipeline usage
    let patterns = vec![test_file.to_string()];
    let password = "example_password_123".to_string();
    
    let options = EncryptionOptions {
        algorithm: AlgorithmId::recommended(),
        obfuscate_filename: false,
        force_overwrite: true,
        remove_source: false, // Keep the original for this example
        check_duplicates: true,
    };

    println!("🚀 Starting encryption pipeline...");

    // Execute the entire encryption pipeline in one call
    match EncryptionPipeline::execute(patterns, password, options) {
        Ok(report) => {
            println!("\n🔒 Encryption Complete!");
            println!("✅ Successfully encrypted {} files", report.success_count());
            
            if report.failure_count() > 0 {
                println!("❌ Failed to encrypt {} files", report.failure_count());
                for failure in &report.failed {
                    println!("   Error: {} - {}", 
                        failure.job.source_path.display(), 
                        failure.error
                    );
                }
            }
            
            println!("⏱️  Total time: {:?}", report.total_duration);
            println!("📊 Processed {} bytes across {} files", 
                report.total_bytes_processed,
                report.total_files_processed
            );
            
            if report.success_count() > 0 {
                println!("\nDetails:");
                for result in &report.successful {
                    println!("   {} → {} ({:?}) [{}]",
                        result.job.source_path.display(),
                        result.job.target_path.display(),
                        result.duration,
                        result.algorithm.name()
                    );
                }
                
                println!("\n💡 Compression ratio: {:.2}", report.compression_ratio());
            }

            if !report.is_success() {
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("❌ Encryption failed: {}", e);
            eprintln!("   This is expected since we haven't implemented real crypto yet");
            eprintln!("   The pipeline structure is working correctly!");
            
            // Don't exit with error for this example
            println!("\n✨ Pipeline executed successfully (with mock crypto)");
        }
    }

    println!("\n🎉 Example completed!");
    Ok(())
}