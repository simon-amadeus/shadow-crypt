//! Shadow migration tool
//! 
//! This tool provides file format migration capabilities for Shadow encrypted files.
//! It can analyze files for migration needs and will support migrating between
//! different versions of the Shadow file format as new versions are released.

use shadow_crypt::shared::{CryptoError, MigrationSystem};
use std::env;
use std::path::Path;
use std::process;

/// Display help information
fn print_help() {
    println!("shadowmigrate - Shadow File Format Migration Tool");
    println!();
    println!("USAGE:");
    println!("    shadowmigrate analyze <file_or_directory>");
    println!("    shadowmigrate --help");
    println!();
    println!("COMMANDS:");
    println!("    analyze    Analyze files for migration requirements");
    println!();
    println!("OPTIONS:");
    println!("    --help     Display this help message");
    println!();
    println!("EXAMPLES:");
    println!("    shadowmigrate analyze secret.shadow");
    println!("    shadowmigrate analyze /path/to/encrypted/files/");
    println!();
    println!("NOTE: This tool currently provides analysis only. Migration execution");
    println!("      will be implemented when multiple format versions exist.");
}

/// Analyze a single file for migration needs
fn analyze_file(file_path: &Path) -> Result<(), CryptoError> {
    let migration_system = MigrationSystem::new();
    
    match migration_system.analyze_file(file_path) {
        Ok(Some(plan)) => {
            println!("File: {}", file_path.display());
            println!("  Current version: {}", plan.source_version);
            println!("  Target version: {}", plan.target_version);
            println!("  Migration steps: {}", plan.estimated_steps);
            println!("  Requires backup: {}", plan.requires_backup);
            println!("  Status: Migration needed");
            println!();
        }
        Ok(None) => {
            println!("File: {}", file_path.display());
            println!("  Status: Already current version (no migration needed)");
            println!();
        }
        Err(e) => {
            println!("File: {}", file_path.display());
            println!("  Status: Analysis failed - {}", e);
            println!();
        }
    }
    
    Ok(())
}

/// Analyze a directory for migration needs
fn analyze_directory(dir_path: &Path) -> Result<(), CryptoError> {
    let migration_system = MigrationSystem::new();
    
    println!("Analyzing directory: {}", dir_path.display());
    println!();
    
    match migration_system.analyze_directory(dir_path) {
        Ok(plans) => {
            if plans.is_empty() {
                println!("No .shadow files found that require migration.");
            } else {
                let plan_count = plans.len();
                println!("Found {} files requiring migration:", plan_count);
                println!();
                
                for plan in plans {
                    println!("  {}", plan.source_path.display());
                    println!("    Version: {} → {}", plan.source_version, plan.target_version);
                    println!("    Steps: {}", plan.estimated_steps);
                    println!();
                }
                
                println!("Summary: {} files need migration", plan_count);
            }
        }
        Err(e) => {
            eprintln!("Error analyzing directory: {}", e);
            return Err(e);
        }
    }
    
    Ok(())
}

/// Main entry point
fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_help();
        process::exit(1);
    }
    
    match args[1].as_str() {
        "--help" | "-h" => {
            print_help();
            process::exit(0);
        }
        "analyze" => {
            if args.len() < 3 {
                eprintln!("Error: Missing file or directory path");
                eprintln!("Usage: shadowmigrate analyze <file_or_directory>");
                process::exit(1);
            }
            
            let path = Path::new(&args[2]);
            
            let result = if path.is_file() {
                analyze_file(path)
            } else if path.is_dir() {
                analyze_directory(path)
            } else {
                eprintln!("Error: Path does not exist or is not a file/directory: {}", path.display());
                process::exit(1);
            };
            
            if let Err(e) = result {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        }
        _ => {
            eprintln!("Error: Unknown command '{}'", args[1]);
            eprintln!();
            print_help();
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_help_display() {
        // This test just ensures the help function doesn't panic
        print_help();
    }

    #[test]
    fn test_analyze_nonexistent_file() {
        let result = analyze_file(Path::new("/nonexistent/file.shadow"));
        // Should handle the error gracefully
        assert!(result.is_ok());
    }

    #[test]
    fn test_analyze_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let result = analyze_directory(temp_dir.path());
        assert!(result.is_ok());
    }
}