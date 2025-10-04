//! CLI interface for shadowmigrate binary
//! 
//! Provides command-line argument parsing and user interface for migration operations.

use crate::migration::{file_analyzer, migration_planner, safety_checker};
use std::env;
use std::path::Path;
use std::process;

/// Main CLI entry point for shadowmigrate binary
pub fn run_migration_cli() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_help();
        process::exit(1);
    }
    
    match args[1].as_str() {
        "analyze" => {
            if args.len() < 3 {
                eprintln!("Error: analyze command requires a file path");
                print_help();
                process::exit(1);
            }
            analyze_file(Path::new(&args[2]));
        }
        "analyze-dir" => {
            if args.len() < 3 {
                eprintln!("Error: analyze-dir command requires a directory path");
                print_help();
                process::exit(1);
            }
            analyze_directory(Path::new(&args[2]));
        }
        "help" | "--help" | "-h" => {
            print_help();
        }
        _ => {
            eprintln!("Error: Unknown command '{}'", args[1]);
            print_help();
            process::exit(1);
        }
    }
}

/// Print help information
pub fn print_help() {
    println!("shadowmigrate - Shadow file format migration tool");
    println!();
    println!("USAGE:");
    println!("    shadowmigrate <COMMAND> [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("    analyze <file>        Analyze a .shadow file for migration needs");
    println!("    analyze-dir <dir>     Analyze all .shadow files in a directory");
    println!("    help                  Show this help message");
    println!();
    println!("EXAMPLES:");
    println!("    shadowmigrate analyze secret.txt.shadow");
    println!("    shadowmigrate analyze-dir encrypted_files/");
    println!();
    println!("This tool analyzes Shadow encrypted files to determine if they need");
    println!("migration to newer file format versions. Migration execution will be");
    println!("available in future releases when format versions change.");
}

/// Analyze a single file for migration needs
fn analyze_file(file_path: &Path) {
    match file_analyzer::analyze_shadow_file(file_path) {
        Ok(Some(analysis)) => {
            println!("File: {}", file_path.display());
            println!("  Current version: {}", analysis.version_info.current);
            println!("  Status: {}", if analysis.version_info.needs_migration {
                "Migration needed"
            } else {
                "Current version - no migration needed"
            });
            
            if analysis.version_info.needs_migration {
                match migration_planner::create_migration_plan(&analysis) {
                    Ok(plan) => {
                        println!("  Migration plan:");
                        println!("    Target version: {}", plan.target_version);
                        println!("    Estimated steps: {}", plan.estimated_steps);
                        println!("    Requires backup: {}", plan.requires_backup);
                        
                        match safety_checker::verify_migration_safety(&plan) {
                            Ok(safety_report) => {
                                println!("  Safety checks: {} passed", safety_report.checks_passed);
                                if !safety_report.warnings.is_empty() {
                                    println!("  Warnings:");
                                    for warning in &safety_report.warnings {
                                        println!("    - {}", warning);
                                    }
                                }
                            }
                            Err(e) => {
                                println!("  Safety check failed: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("  Migration planning failed: {}", e);
                    }
                }
            }
        }
        Ok(None) => {
            println!("File: {}", file_path.display());
            println!("  Status: Not a Shadow encrypted file");
        }
        Err(e) => {
            eprintln!("Error analyzing {}: {}", file_path.display(), e);
        }
    }
}

/// Analyze a directory for migration needs
fn analyze_directory(dir_path: &Path) {
    if !dir_path.is_dir() {
        eprintln!("Error: {} is not a directory", dir_path.display());
        process::exit(1);
    }
    
    match file_analyzer::analyze_directory(dir_path) {
        Ok(analyses) => {
            if analyses.is_empty() {
                println!("No .shadow files found in {}", dir_path.display());
                return;
            }
            
            let migration_needed: Vec<_> = analyses.iter()
                .filter(|a| a.version_info.needs_migration)
                .collect();
            
            println!("Directory: {}", dir_path.display());
            println!("Total .shadow files: {}", analyses.len());
            println!("Files needing migration: {}", migration_needed.len());
            println!();
            
            if !migration_needed.is_empty() {
                println!("Files requiring migration:");
                for analysis in migration_needed {
                    println!("  {} (v{} → current)", 
                           analysis.file_path.file_name()
                               .unwrap_or_default()
                               .to_string_lossy(),
                           analysis.version_info.current);
                }
                println!();
                println!("Run 'shadowmigrate analyze <file>' for detailed migration plans.");
            } else {
                println!("All files are current version - no migration needed.");
            }
        }
        Err(e) => {
            eprintln!("Error analyzing directory {}: {}", dir_path.display(), e);
            process::exit(1);
        }
    }
}